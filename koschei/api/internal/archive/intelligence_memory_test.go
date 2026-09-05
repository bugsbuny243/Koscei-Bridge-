package archive

import (
	"strings"
	"testing"
	"time"
)

func TestIntelligenceTargetHashIsCaseSensitive(t *testing.T) {
	a := intelligenceTargetHash("solana-mainnet", "wallet", "AbCd")
	b := intelligenceTargetHash("solana-mainnet", "wallet", "abcd")
	if a == b {
		t.Fatal("Solana target hash must preserve exact address case")
	}
}

func TestIntelligenceMemoryFilenameDoesNotExposeTarget(t *testing.T) {
	target := "SensitiveWalletAddress123"
	hash := intelligenceTargetHash("solana-mainnet", "wallet", target)
	name := intelligenceMemoryFilename("wallet", "solana-mainnet", hash, time.Date(2026, 9, 5, 15, 0, 0, 0, time.UTC))
	if strings.Contains(name, target) {
		t.Fatalf("memory filename leaked plaintext target: %s", name)
	}
	if !strings.HasSuffix(name, ".json") {
		t.Fatalf("expected json filename, got %s", name)
	}
}

func TestRedactSensitiveMemoryRecurses(t *testing.T) {
	input := map[string]any{
		"wallet":  "public-address",
		"api_key": "should-not-leak",
		"nested": map[string]any{
			"private_key": "never",
			"evidence":    "keep-me",
		},
		"items": []any{map[string]any{"access_token": "never", "signature": "keep-signature"}},
	}
	out := redactSensitiveMemory(input)
	if out["api_key"] != "[REDACTED]" {
		t.Fatalf("api key was not redacted: %#v", out["api_key"])
	}
	nested := out["nested"].(map[string]any)
	if nested["private_key"] != "[REDACTED]" || nested["evidence"] != "keep-me" {
		t.Fatalf("nested redaction mismatch: %#v", nested)
	}
	items := out["items"].([]any)
	item := items[0].(map[string]any)
	if item["access_token"] != "[REDACTED]" || item["signature"] != "keep-signature" {
		t.Fatalf("slice redaction mismatch: %#v", item)
	}
}
