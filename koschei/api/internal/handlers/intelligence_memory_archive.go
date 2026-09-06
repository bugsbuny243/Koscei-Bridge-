package handlers

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"koschei/api/internal/archive"
)

const intelligenceMemoryWriteTimeout = 20 * time.Second

type intelligenceMemoryReceipt struct {
	Status              string               `json:"status"`
	Durable             bool                 `json:"durable"`
	Backend             string               `json:"backend,omitempty"`
	ConfigurationStatus string               `json:"configuration_status,omitempty"`
	Object              *archive.DriveObject `json:"object,omitempty"`
}

func intelligenceMemoryConfigurationStatus() string {
	folderConfigured := strings.TrimSpace(os.Getenv("GOOGLE_DRIVE_ARCHIVE_FOLDER_ID")) != ""
	credentialConfigured := strings.TrimSpace(os.Getenv("GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON")) != ""
	switch {
	case !folderConfigured && !credentialConfigured:
		return "folder_and_credential_missing"
	case !folderConfigured:
		return "folder_missing"
	case !credentialConfigured:
		return "credential_missing"
	default:
		return "configured"
	}
}

// archiveIntelligenceMemory is deliberately best-effort. A Drive outage must
// never suppress or alter a completed ARVIS result. Neon/PostgreSQL is not part
// of this path; durable intelligence memory belongs in Google Drive.
func archiveIntelligenceMemory(ctx context.Context, kind, network, target string, payload any) intelligenceMemoryReceipt {
	configurationStatus := intelligenceMemoryConfigurationStatus()
	baseReceipt := intelligenceMemoryReceipt{
		Backend:             "google_drive",
		ConfigurationStatus: configurationStatus,
	}
	if strings.TrimSpace(target) == "" {
		baseReceipt.Status = "invalid_target"
		return baseReceipt
	}

	drive, err := archive.NewGoogleDriveFromEnv()
	if err != nil {
		baseReceipt.Status = "drive_unavailable"
		if configurationStatus == "configured" {
			baseReceipt.ConfigurationStatus = "credential_invalid_or_incomplete"
		}
		return baseReceipt
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		baseReceipt.Status = "encode_failed"
		return baseReceipt
	}
	memory := map[string]any{}
	if err := json.Unmarshal(encoded, &memory); err != nil {
		baseReceipt.Status = "encode_failed"
		return baseReceipt
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
		baseReceipt.Status = status
		return baseReceipt
	}
	object := result.Object
	baseReceipt.Status = result.Status
	baseReceipt.Durable = result.Status == "drive_archived"
	baseReceipt.ConfigurationStatus = "ready"
	baseReceipt.Object = &object
	return baseReceipt
}

func (h *Handler) archiveIntelligenceMemory(ctx context.Context, kind, network, target string, payload any) intelligenceMemoryReceipt {
	return archiveIntelligenceMemory(ctx, kind, network, target, payload)
}
