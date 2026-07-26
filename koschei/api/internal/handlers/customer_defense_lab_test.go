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
	payload := string(encoded)
	for _, forbidden := range []string{"created_by", "customer-a", "source_uri", "source_commit", "secret-commit", "metadata", "private\\\":\\\"source", "content"} {
		if strings.Contains(strings.ToLower(payload), strings.ToLower(forbidden)) {
			t.Fatalf("customer artifact response leaked %q: %s", forbidden, payload)
		}
	}
	for _, required := range []string{"artifact_ref", "program_id", "content_hash", "private"} {
		if required == "private" {
			continue
		}
		if !strings.Contains(payload, required) {
			t.Fatalf("customer artifact response missing %q: %s", required, payload)
		}
	}
}
