package handlers

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"koschei/api/internal/archive"
)

const intelligenceMemoryWriteTimeout = 20 * time.Second

type intelligenceMemoryReceipt struct {
	Status  string               `json:"status"`
	Durable bool                 `json:"durable"`
	Object  *archive.DriveObject `json:"object,omitempty"`
}

// archiveIntelligenceMemory is deliberately best-effort. A Drive outage must
// never suppress or alter a completed ARVIS result. Neon/PostgreSQL is not part
// of this path; durable intelligence memory belongs in Google Drive.
func (h *Handler) archiveIntelligenceMemory(ctx context.Context, kind, network, target string, payload any) intelligenceMemoryReceipt {
	if strings.TrimSpace(target) == "" {
		return intelligenceMemoryReceipt{Status: "invalid_target"}
	}

	drive, err := archive.NewGoogleDriveFromEnv()
	if err != nil {
		return intelligenceMemoryReceipt{Status: "drive_unavailable"}
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return intelligenceMemoryReceipt{Status: "encode_failed"}
	}
	memory := map[string]any{}
	if err := json.Unmarshal(encoded, &memory); err != nil {
		return intelligenceMemoryReceipt{Status: "encode_failed"}
	}

	if ctx == nil {
		ctx = context.Background()
	}
	writeCtx, cancel := context.WithTimeout(ctx, intelligenceMemoryWriteTimeout)
	defer cancel()

	result, err := drive.PutIntelligenceMemory(writeCtx, kind, network, target, memory)
	if err != nil {
		status := strings.TrimSpace(result.Status)
		if status == "" {
			status = "drive_write_failed"
		}
		return intelligenceMemoryReceipt{Status: status}
	}
	object := result.Object
	return intelligenceMemoryReceipt{Status: result.Status, Durable: result.Status == "drive_archived", Object: &object}
}
