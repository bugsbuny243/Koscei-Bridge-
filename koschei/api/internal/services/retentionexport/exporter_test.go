package retentionexport

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeRepository struct {
	rows          []ArchiveRow
	exported      map[int64]bool
	markCalls     int
	startCalls    int
	finishCalls   int
	lastFinishErr error
}

func (r *fakeRepository) TryLock(context.Context) (func(), bool, error) {
	return func() {}, true, nil
}

func (r *fakeRepository) StartRun(context.Context, string) (string, error) {
	r.startCalls++
	return "run-1", nil
}

func (r *fakeRepository) LoadPending(_ context.Context, limit int) ([]ArchiveRow, error) {
	out := []ArchiveRow{}
	for _, row := range r.rows {
		if r.exported[row.ID] {
			continue
		}
		out = append(out, row)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (r *fakeRepository) MarkExported(_ context.Context, _ string, rows []ArchiveRow, exportRef, batchChecksum string) error {
	if !strings.Contains(exportRef, "#sha256="+batchChecksum) {
		return errors.New("export ref missing checksum")
	}
	r.markCalls++
	for _, row := range rows {
		r.exported[row.ID] = true
	}
	return nil
}

func (r *fakeRepository) FinishRun(_ context.Context, _ string, _ Result, runErr error) error {
	r.finishCalls++
	r.lastFinishErr = runErr
	return nil
}

type fakeSink struct {
	objects     map[string][]byte
	writeErr    error
	readErr     error
	corruptRead bool
	writeCalls  int
	readCalls   int
}

func (s *fakeSink) Name() string { return "fake" }

func (s *fakeSink) Put(_ context.Context, key string, data []byte) (string, error) {
	s.writeCalls++
	if s.writeErr != nil {
		return "", s.writeErr
	}
	s.objects[key] = append([]byte(nil), data...)
	return "fake://" + key, nil
}

func (s *fakeSink) Get(_ context.Context, key string) ([]byte, error) {
	s.readCalls++
	if s.readErr != nil {
		return nil, s.readErr
	}
	data := append([]byte(nil), s.objects[key]...)
	if s.corruptRead {
		data = append(data, 'x')
	}
	return data, nil
}

func TestExporterSuccessfulExport(t *testing.T) {
	repository := newFakeRepository(testArchiveRows())
	sink := &fakeSink{objects: map[string][]byte{}}
	result, err := (Exporter{
		Repository: repository,
		Sink:       sink,
		Config:     Config{Sink: "fake", BatchSize: 10, MaxBatches: 1, Prefix: "tests"},
	}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.ExportedRows != 2 || result.ObjectCount != 1 || repository.markCalls != 1 {
		t.Fatalf("result=%+v mark_calls=%d", result, repository.markCalls)
	}
	if !repository.exported[1] || !repository.exported[2] {
		t.Fatalf("expected both rows exported: %#v", repository.exported)
	}
	if sink.writeCalls != 1 || sink.readCalls != 1 || repository.lastFinishErr != nil {
		t.Fatalf("write=%d read=%d finish_err=%v", sink.writeCalls, sink.readCalls, repository.lastFinishErr)
	}
}

func TestExporterWriteFailureLeavesWholeBatchUnexported(t *testing.T) {
	repository := newFakeRepository(testArchiveRows())
	sink := &fakeSink{objects: map[string][]byte{}, writeErr: errors.New("sink unavailable")}
	_, err := (Exporter{Repository: repository, Sink: sink, Config: Config{Sink: "fake", BatchSize: 10}}).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "sink unavailable") {
		t.Fatalf("expected sink failure, got %v", err)
	}
	if repository.markCalls != 0 || len(repository.exported) != 0 {
		t.Fatalf("batch was partially marked: calls=%d exported=%#v", repository.markCalls, repository.exported)
	}
}

func TestExporterChecksumMismatchLeavesWholeBatchUnexported(t *testing.T) {
	repository := newFakeRepository(testArchiveRows())
	sink := &fakeSink{objects: map[string][]byte{}, corruptRead: true}
	result, err := (Exporter{Repository: repository, Sink: sink, Config: Config{Sink: "fake", BatchSize: 10}}).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
	if result.ChecksumMismatches != 1 || repository.markCalls != 0 || len(repository.exported) != 0 {
		t.Fatalf("result=%+v mark_calls=%d exported=%#v", result, repository.markCalls, repository.exported)
	}
}

func TestExporterResumeSkipsAlreadyExportedRow(t *testing.T) {
	repository := newFakeRepository(testArchiveRows())
	repository.exported[1] = true
	sink := &fakeSink{objects: map[string][]byte{}}
	result, err := (Exporter{Repository: repository, Sink: sink, Config: Config{Sink: "fake", BatchSize: 10}}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.SelectedRows != 1 || result.ExportedRows != 1 || !repository.exported[2] {
		t.Fatalf("result=%+v exported=%#v", result, repository.exported)
	}
	for _, object := range sink.objects {
		lines := strings.Split(strings.TrimSpace(string(object)), "\n")
		if len(lines) != 1 || strings.Contains(lines[0], `"archive_id":1`) {
			t.Fatalf("resume object included an already exported row: %s", object)
		}
	}
}

func TestExporterDisabledIsNoOp(t *testing.T) {
	repository := newFakeRepository(testArchiveRows())
	result, err := (Exporter{Repository: repository, Config: Config{Sink: "disabled"}}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Enabled || repository.startCalls != 0 || repository.finishCalls != 0 {
		t.Fatalf("result=%+v start=%d finish=%d", result, repository.startCalls, repository.finishCalls)
	}
}

func newFakeRepository(rows []ArchiveRow) *fakeRepository {
	return &fakeRepository{rows: rows, exported: map[int64]bool{}}
}

func testArchiveRows() []ArchiveRow {
	stamp := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	return []ArchiveRow{
		{ID: 1, RunID: "retention-1", SourceTable: "security_radar_events", SourceID: "11", RowChecksum: strings.Repeat("a", 64), Payload: json.RawMessage(`{"id":11}`), ArchivedAt: stamp},
		{ID: 2, RunID: "retention-1", SourceTable: "security_radar_events", SourceID: "12", RowChecksum: strings.Repeat("b", 64), Payload: json.RawMessage(`{"id":12}`), ArchivedAt: stamp.Add(time.Second)},
	}
}
