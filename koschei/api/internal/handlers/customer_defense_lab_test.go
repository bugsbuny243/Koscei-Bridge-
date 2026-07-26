package handlers

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"koschei/api/internal/defense"
)

func TestCustomerArtifactViewRedactsCrossAccountMetadata(t *testing.T) {
	item := defense.Artifact{
		ArtifactRef: "KDA1-0123456789abcdef0123456789abcdef",
		ProgramID: "Program111", Network: "solana-mainnet", ArtifactType: "source_bundle",
		SourceURI: "private://customer-a/repository", SourceCommit: "secret-commit",
		ContentHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ContentEncoding: "json", Content: []byte(`{"private":"source"}`),
		Metadata: map[string]any{"customer": "customer-a"}, TrustLevel: "unverified",
		Verified: false, CreatedBy: "user:customer-a", CreatedAt: time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
	}
	encoded, err := json.Marshal(customerSafeArtifactView(item))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"created_by", "source_uri", "source_commit", "metadata", "content"} {
		if _, exists := payload[forbidden]; exists {
			t.Fatalf("customer artifact response leaked key %q: %s", forbidden, encoded)
		}
	}
	for _, required := range []string{"artifact_ref", "program_id", "network", "artifact_type", "content_hash", "content_encoding", "trust_level", "verified", "created_at"} {
		if _, exists := payload[required]; !exists {
			t.Fatalf("customer artifact response missing key %q: %s", required, encoded)
		}
	}
	text := strings.ToLower(string(encoded))
	for _, forbiddenValue := range []string{"customer-a", "secret-commit", "private://"} {
		if strings.Contains(text, strings.ToLower(forbiddenValue)) {
			t.Fatalf("customer artifact response leaked value %q: %s", forbiddenValue, text)
		}
	}
}
