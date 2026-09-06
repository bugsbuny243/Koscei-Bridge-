package handlers

import (
	"context"
	"strings"
	"time"

	"koschei/api/internal/archive"
)

const intelligenceMemoryReadTimeout = 12 * time.Second

type intelligenceMemoryReadReceipt struct {
	Status              string                 `json:"status"`
	Available           bool                   `json:"available"`
	Backend             string                 `json:"backend"`
	ConfigurationStatus string                 `json:"configuration_status,omitempty"`
	Kind                string                 `json:"kind,omitempty"`
	Network             string                 `json:"network,omitempty"`
	CapturedAt          time.Time              `json:"captured_at,omitempty"`
	Object              *archive.DriveObject   `json:"object,omitempty"`
	Payload             map[string]any         `json:"payload,omitempty"`
	Limitations         []string               `json:"limitations"`
}

func loadLatestIntelligenceMemory(ctx context.Context, kind, network, target string) intelligenceMemoryReadReceipt {
	configurationStatus := intelligenceMemoryConfigurationStatus()
	out := intelligenceMemoryReadReceipt{
		Status:              "not_loaded",
		Backend:             "google_drive",
		ConfigurationStatus: configurationStatus,
		Kind:                strings.TrimSpace(kind),
		Network:             strings.TrimSpace(network),
		Limitations:         []string{},
	}
	if strings.TrimSpace(target) == "" {
		out.Status = "invalid_target"
		out.Limitations = append(out.Limitations, "Historical intelligence memory was not loaded because the target is empty.")
		return out
	}
	drive, err := archive.NewGoogleDriveFromEnv()
	if err != nil {
		out.Status = "drive_unavailable"
		if configurationStatus == "configured" {
			out.ConfigurationStatus = "credential_invalid_or_incomplete"
		}
		out.Limitations = append(out.Limitations, "Historical intelligence memory is unavailable because the Google Drive archive is not ready; this is a memory collection gap, not evidence that no prior history exists.")
		return out
	}
	if ctx == nil {
		ctx = context.Background()
	}
	readCtx, cancel := context.WithTimeout(ctx, intelligenceMemoryReadTimeout)
	defer cancel()
	envelope, object, err := drive.GetLatestIntelligenceMemory(readCtx, kind, network, target)
	if err != nil {
		out.Status = "not_found_or_unavailable"
		out.ConfigurationStatus = "ready"
		out.Limitations = append(out.Limitations, "No verified historical snapshot was returned from Drive. This does not prove that the target has no prior on-chain history.")
		return out
	}
	out.Status = "verified_history_available"
	out.Available = true
	out.ConfigurationStatus = "ready"
	out.Kind = envelope.Kind
	out.Network = envelope.Network
	out.CapturedAt = envelope.CapturedAt
	out.Object = &object
	out.Payload = envelope.Payload
	out.Limitations = append(out.Limitations,
		"Historical Drive memory is contextual evidence only; fresh on-chain collection takes precedence when the two differ.",
		"A prior ARVIS snapshot is not proof that the underlying chain state is unchanged.",
	)
	return out
}

func (h *Handler) loadLatestIntelligenceMemory(ctx context.Context, kind, network, target string) intelligenceMemoryReadReceipt {
	return loadLatestIntelligenceMemory(ctx, kind, network, target)
}
