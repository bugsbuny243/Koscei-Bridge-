package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveCanonicalCreatorSourceContextFromSolscan(t *testing.T) {
	const mint = "9cRCn9rGT8V2imeM2BaKs13yhMEais3ruM3rPvTGpump"
	const creator = "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdCsvHcx6PRe"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token/meta" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"address":"` + mint + `","name":"The Black Bull","symbol":"ANSEM","creator":"` + creator + `","create_tx":"create-signature","created_time":1784480000}}`))
	}))
	defer server.Close()

	t.Setenv("SOLSCAN_API_KEY", "test-key")
	t.Setenv("SOLSCAN_API_BASE_URL", server.URL)
	out := (&Handler{}).resolveCanonicalCreatorSourceContext(context.Background(), mint, "solana-mainnet", "owner_full_scan", map[string]any{"available": false})
	if got := creatorIntelCleanString(out["creator_wallet"]); got != creator {
		t.Fatalf("creator not resolved: %q", got)
	}
	if got := creatorIntelCleanString(out["creator_resolution_status"]); got != "observed_external_attribution" {
		t.Fatalf("unexpected resolution status: %q", got)
	}
	if verified, _ := out["creator_relation_verified"].(bool); verified {
		t.Fatal("external attribution must not be marked verified")
	}
	if got := creatorIntelCleanString(out["creation_signature"]); got != "create-signature" {
		t.Fatalf("creation signature not projected: %q", got)
	}
}

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

func TestResolveCanonicalCreatorSourceContextStoredOnlySkipsNetwork(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()

	t.Setenv("SOLSCAN_API_KEY", "test-key")
	t.Setenv("SOLSCAN_API_BASE_URL", server.URL)
	out := (&Handler{}).resolveCanonicalCreatorSourceContext(context.Background(), "mint", "solana-mainnet", "stored_only_projection", map[string]any{})
	if called {
		t.Fatal("stored-only projection called Solscan")
	}
	if got := creatorIntelCleanString(out["creator_resolution_status"]); got != "not_requested" {
		t.Fatalf("unexpected stored-only status: %q", got)
	}
}
