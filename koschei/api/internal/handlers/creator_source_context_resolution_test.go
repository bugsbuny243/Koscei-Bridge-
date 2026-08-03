package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveCanonicalCreatorSourceContextKeepsExistingCreator(t *testing.T) {
	const creator = "ExistingCreator11111111111111111111111111111"
	out := (&Handler{}).resolveCanonicalCreatorSourceContext(context.Background(), "mint", "solana-mainnet", "owner_full_scan", map[string]any{
		"available":                 true,
		"source":                    "pumpportal",
		"creator_wallet":            creator,
		"creator_relation_verified": true,
	})
	if got := creatorIntelCleanString(out["creator_wallet"]); got != creator {
		t.Fatalf("existing creator changed: %q", got)
	}
	if got := creatorIntelCleanString(out["creator_resolution_status"]); got != "source_context" {
		t.Fatalf("unexpected existing-source status: %q", got)
	}
}

func TestResolveCanonicalCreatorSourceContextStoredOnlySkipsHelius(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()

	t.Setenv("HELIUS_API_KEY", "test-key")
	t.Setenv("SOLANA_RPC_URL", server.URL)
	out := (&Handler{}).resolveCanonicalCreatorSourceContext(context.Background(), "mint", "solana-mainnet", "stored_only_projection", map[string]any{})
	if called {
		t.Fatal("stored-only projection called Helius")
	}
	if got := creatorIntelCleanString(out["creator_resolution_status"]); got != "not_requested" {
		t.Fatalf("unexpected stored-only status: %q", got)
	}
}

func TestCloneCreatorSourceContextPreservesSafetyDefaults(t *testing.T) {
	out := cloneCreatorSourceContext(map[string]any{"source": "fixture"})
	if available, ok := out["available"].(bool); !ok || available {
		t.Fatalf("unexpected available default: %#v", out["available"])
	}
	if claimed, ok := out["identity_claimed"].(bool); !ok || claimed {
		t.Fatalf("unexpected identity default: %#v", out["identity_claimed"])
	}
}
