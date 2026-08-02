package retentionexport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

// Sink stores an immutable export object and can read the exact bytes back for
// destination verification. Implementations must use key as an object-relative
// identifier and return a stable locator from Put.
type Sink interface {
	Name() string
	Put(ctx context.Context, key string, data []byte) (string, error)
	Get(ctx context.Context, key string) ([]byte, error)
}

// ArchiveRow is the complete export contract for one staging-ledger row.
type ArchiveRow struct {
	ID          int64
	RunID       string
	SourceTable string
	SourceID    string
	RowChecksum string
	Payload     json.RawMessage
	ArchivedAt  time.Time
}

// Repository isolates the exporter state machine from PostgreSQL so all
// write/read-back/failure paths can be tested without weakening the SQL path.
type Repository interface {
	TryLock(ctx context.Context) (release func(), acquired bool, err error)
	StartRun(ctx context.Context, sink string) (string, error)
	LoadPending(ctx context.Context, limit int) ([]ArchiveRow, error)
	MarkExported(ctx context.Context, runID string, rows []ArchiveRow, exportRef, batchChecksum string) error
	FinishRun(ctx context.Context, runID string, result Result, runErr error) error
}

type Config struct {
	Sink       string
	BatchSize  int
	MaxBatches int
	Prefix     string

	FilesystemPath string

	S3Endpoint        string
	S3Bucket          string
	S3Region          string
	S3AccessKeyID     string
	S3SecretAccessKey string
	S3SessionToken    string
	S3PathStyle       bool
}

type Result struct {
	Enabled            bool
	LockAcquired       bool
	RunID              string
	Sink               string
	SelectedRows       int64
	ExportedRows       int64
	ObjectCount        int64
	BytesExported      int64
	ChecksumMismatches int64
	LastExportRef      string
}

type Exporter struct {
	Repository Repository
	Sink       Sink
	Config     Config
}

func (e Exporter) Run(ctx context.Context) (result Result, runErr error) {
	result.Enabled = !strings.EqualFold(strings.TrimSpace(e.Config.Sink), "disabled")
	if !result.Enabled {
		return result, nil
	}
	if e.Repository == nil {
		return result, errors.New("retention export repository is required")
	}
	if e.Sink == nil {
		return result, errors.New("retention export sink is required")
	}
	result.Sink = e.Sink.Name()

	release, acquired, err := e.Repository.TryLock(ctx)
	if err != nil {
		return result, fmt.Errorf("retention export lock: %w", err)
	}
	result.LockAcquired = acquired
	if !acquired {
		return result, nil
	}
	defer release()

	runID, err := e.Repository.StartRun(ctx, result.Sink)
	if err != nil {
		return result, fmt.Errorf("retention export run ledger: %w", err)
	}
	result.RunID = runID
	defer func() {
		finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if finishErr := e.Repository.FinishRun(finishCtx, runID, result, runErr); finishErr != nil && runErr == nil {
			runErr = fmt.Errorf("retention export finish ledger: %w", finishErr)
		}
	}()

	batchSize := e.Config.BatchSize
	if batchSize <= 0 {
		batchSize = 500
	}
	maxBatches := e.Config.MaxBatches
	if maxBatches <= 0 {
		maxBatches = 10
	}
	prefix := strings.Trim(strings.TrimSpace(e.Config.Prefix), "/")
	if prefix == "" {
		prefix = "radar-retention"
	}

	for batchIndex := 0; batchIndex < maxBatches; batchIndex++ {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		rows, err := e.Repository.LoadPending(ctx, batchSize)
		if err != nil {
			return result, fmt.Errorf("load pending retention archive: %w", err)
		}
		if len(rows) == 0 {
			return result, nil
		}
		result.SelectedRows += int64(len(rows))

		serialized, err := serializeBatch(rows)
		if err != nil {
			return result, fmt.Errorf("serialize retention archive batch: %w", err)
		}
		checksum := sha256Hex(serialized)
		key := batchObjectKey(prefix, rows, checksum)
		locator, err := e.Sink.Put(ctx, key, serialized)
		if err != nil {
			return result, fmt.Errorf("write retention archive batch: %w", err)
		}
		readBack, err := e.Sink.Get(ctx, key)
		if err != nil {
			return result, fmt.Errorf("read back retention archive batch: %w", err)
		}
		readBackChecksum := sha256Hex(readBack)
		if readBackChecksum != checksum {
			result.ChecksumMismatches++
			return result, fmt.Errorf("retention archive destination checksum mismatch: wrote=%s read=%s", checksum, readBackChecksum)
		}
		exportRef := strings.TrimSpace(locator) + "#sha256=" + checksum
		if err := e.Repository.MarkExported(ctx, runID, rows, exportRef, checksum); err != nil {
			return result, fmt.Errorf("mark retention archive exported: %w", err)
		}
		result.ExportedRows += int64(len(rows))
		result.ObjectCount++
		result.BytesExported += int64(len(serialized))
		result.LastExportRef = exportRef

		if len(rows) < batchSize {
			return result, nil
		}
	}
	return result, nil
}

type exportedArchiveLine struct {
	ArchiveID   int64           `json:"archive_id"`
	RunID       string          `json:"run_id"`
	SourceTable string          `json:"source_table"`
	SourceID    string          `json:"source_id"`
	RowChecksum string          `json:"row_checksum"`
	Payload     json.RawMessage `json:"payload"`
	ArchivedAt  time.Time       `json:"archived_at"`
}

func serializeBatch(rows []ArchiveRow) ([]byte, error) {
	out := make([]byte, 0, len(rows)*256)
	for _, row := range rows {
		if row.ID <= 0 || strings.TrimSpace(row.SourceTable) == "" || strings.TrimSpace(row.SourceID) == "" {
			return nil, fmt.Errorf("invalid archive row id=%d table=%q source_id=%q", row.ID, row.SourceTable, row.SourceID)
		}
		if len(row.Payload) == 0 || !json.Valid(row.Payload) {
			return nil, fmt.Errorf("archive row %d has invalid payload", row.ID)
		}
		line, err := json.Marshal(exportedArchiveLine{
			ArchiveID:   row.ID,
			RunID:       strings.TrimSpace(row.RunID),
			SourceTable: strings.TrimSpace(row.SourceTable),
			SourceID:    strings.TrimSpace(row.SourceID),
			RowChecksum: strings.TrimSpace(row.RowChecksum),
			Payload:     row.Payload,
			ArchivedAt:  row.ArchivedAt.UTC(),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, line...)
		out = append(out, '\n')
	}
	return out, nil
}

func batchObjectKey(prefix string, rows []ArchiveRow, checksum string) string {
	firstID, lastID := rows[0].ID, rows[len(rows)-1].ID
	stamp := rows[0].ArchivedAt.UTC()
	datePath := "unknown-date"
	if !stamp.IsZero() {
		datePath = stamp.Format("2006/01/02")
	}
	name := fmt.Sprintf("%d-%d-%s.ndjson", firstID, lastID, checksum)
	return path.Join(prefix, datePath, name)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
