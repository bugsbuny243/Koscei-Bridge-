package handlers

import (
	"context"
	"testing"
)

func TestArchiveIntelligenceMemoryWithoutDriveConfigurationIsNonBlocking(t *testing.T) {
	t.Setenv("GOOGLE_DRIVE_ARCHIVE_FOLDER_ID", "")
	t.Setenv("GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON", "")

	receipt := (&Handler{}).archiveIntelligenceMemory(context.Background(), "wallet_investigation", "solana-mainnet", "Wallet111", map[string]any{
		"ok":       true,
		"evidence": []any{"sig-1"},
	})
	if receipt.Status != "drive_unavailable" {
		t.Fatalf("status=%q want drive_unavailable", receipt.Status)
	}
	if receipt.Durable {
		t.Fatal("unconfigured Drive archive must not claim durable memory")
	}
	if receipt.Object != nil {
		t.Fatalf("unconfigured Drive archive returned object: %#v", receipt.Object)
	}
}
