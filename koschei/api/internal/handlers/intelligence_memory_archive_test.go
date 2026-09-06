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
	if receipt.Backend != "google_drive" {
		t.Fatalf("backend=%q want google_drive", receipt.Backend)
	}
	if receipt.ConfigurationStatus != "folder_and_credential_missing" {
		t.Fatalf("configuration_status=%q want folder_and_credential_missing", receipt.ConfigurationStatus)
	}
	if receipt.Durable {
		t.Fatal("unconfigured Drive archive must not claim durable memory")
	}
	if receipt.Object != nil {
		t.Fatalf("unconfigured Drive archive returned object: %#v", receipt.Object)
	}
}

func TestArchiveIntelligenceMemoryReportsCredentialMissingWithoutLeakingSecret(t *testing.T) {
	t.Setenv("GOOGLE_DRIVE_ARCHIVE_FOLDER_ID", "folder-123")
	t.Setenv("GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON", "")

	receipt := (&Handler{}).archiveIntelligenceMemory(context.Background(), "token_investigation", "solana-mainnet", "Mint111", map[string]any{"ok": true})
	if receipt.Status != "drive_unavailable" {
		t.Fatalf("status=%q want drive_unavailable", receipt.Status)
	}
	if receipt.ConfigurationStatus != "credential_missing" {
		t.Fatalf("configuration_status=%q want credential_missing", receipt.ConfigurationStatus)
	}
	if receipt.Durable {
		t.Fatal("missing credential must not claim durable memory")
	}
}

func TestArchiveIntelligenceMemoryReportsFolderMissing(t *testing.T) {
	t.Setenv("GOOGLE_DRIVE_ARCHIVE_FOLDER_ID", "")
	t.Setenv("GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON", `{"client_email":"svc@example.test","private_key":"not-used"}`)

	receipt := (&Handler{}).archiveIntelligenceMemory(context.Background(), "wallet_investigation", "solana-mainnet", "Wallet111", map[string]any{"ok": true})
	if receipt.Status != "drive_unavailable" {
		t.Fatalf("status=%q want drive_unavailable", receipt.Status)
	}
	if receipt.ConfigurationStatus != "folder_missing" {
		t.Fatalf("configuration_status=%q want folder_missing", receipt.ConfigurationStatus)
	}
}

func TestArchiveIntelligenceMemoryReportsInvalidConfiguredCredential(t *testing.T) {
	t.Setenv("GOOGLE_DRIVE_ARCHIVE_FOLDER_ID", "folder-123")
	t.Setenv("GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON", `{}`)

	receipt := (&Handler{}).archiveIntelligenceMemory(context.Background(), "wallet_investigation", "solana-mainnet", "Wallet111", map[string]any{"ok": true})
	if receipt.Status != "drive_unavailable" {
		t.Fatalf("status=%q want drive_unavailable", receipt.Status)
	}
	if receipt.ConfigurationStatus != "credential_invalid_or_incomplete" {
		t.Fatalf("configuration_status=%q want credential_invalid_or_incomplete", receipt.ConfigurationStatus)
	}
}
