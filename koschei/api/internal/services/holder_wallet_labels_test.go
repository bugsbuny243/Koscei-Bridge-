package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type heliusIdentityRewriteTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (transport heliusIdentityRewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.URL.Scheme = transport.target.Scheme
	clone.URL.Host = transport.target.Host
	return transport.base.RoundTrip(clone)
}

func useHeliusIdentityTestServer(t *testing.T, handler http.Handler) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	setHeliusIdentityHTTPClientForTest(&http.Client{
		Transport: heliusIdentityRewriteTransport{target: target, base: server.Client().Transport},
	})
	return server, &calls
}

func TestHeliusWalletIdentityDisabledByDefault(t *testing.T) {
	resetHeliusWalletIdentityStateForTest()
	t.Cleanup(resetHeliusWalletIdentityStateForTest)
	t.Setenv("HELIUS_WALLET_IDENTITY_ENABLED", "")
	t.Setenv("HELIUS_API_KEY", "configured-key")

	_, calls := useHeliusIdentityTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("wallet identity must not call Helius without explicit opt-in")
	}))

	if label := ResolveWalletLabel(t.Context(), "", "Wallet1111111111111111111111111111111111111"); label != nil {
		t.Fatalf("disabled wallet identity returned a label: %#v", label)
	}
	if *calls != 0 {
		t.Fatalf("disabled wallet identity made %d provider calls", *calls)
	}
}

func TestHeliusWalletIdentityBatchesMultipleAddressesIntoOneRequest(t *testing.T) {
	resetHeliusWalletIdentityStateForTest()
	t.Cleanup(resetHeliusWalletIdentityStateForTest)
	t.Setenv("HELIUS_WALLET_IDENTITY_ENABLED", "true")
	t.Setenv("HELIUS_API_KEY", "paid-plan-key")

	addresses := []string{
		"Wallet1111111111111111111111111111111111111",
		"Wallet2222222222222222222222222222222222222",
		"Wallet3333333333333333333333333333333333333",
	}
	_, calls := useHeliusIdentityTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/wallet/batch-identity" {
			t.Fatalf("unexpected identity request: %s %s", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("api-key") != "" {
			t.Fatal("wallet identity API key must not be placed in the request URL")
		}
		if got := r.Header.Get("X-Api-Key"); got != "paid-plan-key" {
			t.Fatalf("unexpected X-Api-Key header: %q", got)
		}
		var payload struct {
			Addresses []string `json:"addresses"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if len(payload.Addresses) != len(addresses) {
			t.Fatalf("expected %d batched addresses, got %#v", len(addresses), payload.Addresses)
		}
		w.Header().Set("Content-Type", "application/json")
		// Deliberately return rows out of request order. Evidence attribution
		// must bind by exact address, never array position.
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"address": addresses[2], "type": "market_maker", "name": "Market Maker", "category": "Market Maker", "tags": []string{}},
			{"address": addresses[0], "type": "exchange", "name": "Binance 1", "category": "Centralized Exchange", "tags": []string{"Centralized Exchange"}},
			{"address": addresses[1], "type": "protocol", "name": "Protocol Treasury", "category": "DeFi Protocol", "tags": []string{"Treasury"}},
		})
	}))

	labels := ResolveWalletLabels(t.Context(), "", addresses)
	if *calls != 1 {
		t.Fatalf("expected one 100-credit batch request, got %d requests", *calls)
	}
	if labels[addresses[0]] == nil || labels[addresses[0]].Entity != "Binance 1" {
		t.Fatalf("unexpected first identity: %#v", labels[addresses[0]])
	}
	if labels[addresses[1]] == nil || labels[addresses[1]].Category != "DeFi Protocol" {
		t.Fatalf("unexpected second identity: %#v", labels[addresses[1]])
	}
	if labels[addresses[2]] == nil || labels[addresses[2]].Entity != "Market Maker" || labels[addresses[2]].Source != "helius_identity" {
		t.Fatalf("unexpected third identity: %#v", labels[addresses[2]])
	}
}

func TestHeliusWalletIdentity403TripsProcessCapabilityCircuit(t *testing.T) {
	resetHeliusWalletIdentityStateForTest()
	t.Cleanup(resetHeliusWalletIdentityStateForTest)
	t.Setenv("HELIUS_WALLET_IDENTITY_ENABLED", "1")
	t.Setenv("HELIUS_API_KEY", "free-plan-key")

	_, calls := useHeliusIdentityTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))

	if label := ResolveWalletLabel(t.Context(), "", "Wallet4111111111111111111111111111111111111"); label != nil {
		t.Fatalf("403 response returned a label: %#v", label)
	}
	if label := ResolveWalletLabel(t.Context(), "", "Wallet4222222222222222222222222222222222222"); label != nil {
		t.Fatalf("capability-circuit response returned a label: %#v", label)
	}
	if *calls != 1 {
		t.Fatalf("expected one provider call before the 403 circuit opened, got %d", *calls)
	}
	if !heliusWalletIdentityUnavailable() {
		t.Fatal("expected wallet identity capability circuit to be unavailable after 403")
	}
}

func TestHeliusWalletIdentitySingleWrapperUsesBatchAndCaches(t *testing.T) {
	resetHeliusWalletIdentityStateForTest()
	t.Cleanup(resetHeliusWalletIdentityStateForTest)
	t.Setenv("HELIUS_WALLET_IDENTITY_ENABLED", "true")
	t.Setenv("HELIUS_API_KEY", "paid-plan-key")

	address := "Wallet4444444444444444444444444444444444444"
	_, calls := useHeliusIdentityTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"address": address, "type": "exchange", "name": "Binance 1", "category": "Centralized Exchange", "tags": []string{"Centralized Exchange"}},
		})
	}))

	first := ResolveWalletLabel(t.Context(), "", address)
	second := ResolveWalletLabel(t.Context(), "", address)
	if first == nil || second == nil {
		t.Fatalf("expected cached wallet label, first=%#v second=%#v", first, second)
	}
	if first.Entity != "Binance 1" || first.Source != "helius_identity" {
		t.Fatalf("unexpected wallet label: %#v", first)
	}
	if *calls != 1 {
		t.Fatalf("expected positive identity result to be cached, got %d requests", *calls)
	}
}

func TestHeliusWalletIdentityConfirmedUnknownIsNegativeCached(t *testing.T) {
	resetHeliusWalletIdentityStateForTest()
	t.Cleanup(resetHeliusWalletIdentityStateForTest)
	t.Setenv("HELIUS_WALLET_IDENTITY_ENABLED", "true")
	t.Setenv("HELIUS_API_KEY", "paid-plan-key")

	address := "Wallet5555555555555555555555555555555555555"
	_, calls := useHeliusIdentityTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"address": address, "type": "unknown", "name": "", "category": "", "tags": []string{}},
		})
	}))

	if label := ResolveWalletLabel(t.Context(), "", address); label != nil {
		t.Fatalf("confirmed unknown unexpectedly returned a label: %#v", label)
	}
	if label := ResolveWalletLabel(t.Context(), "", address); label != nil {
		t.Fatalf("cached confirmed unknown unexpectedly returned a label: %#v", label)
	}
	if *calls != 1 {
		t.Fatalf("expected confirmed unknown to be cached after one request, got %d", *calls)
	}
}

func TestHeliusWalletIdentityMissingKeyIsNotCachedAsUnknown(t *testing.T) {
	resetHeliusWalletIdentityStateForTest()
	t.Cleanup(resetHeliusWalletIdentityStateForTest)
	t.Setenv("HELIUS_WALLET_IDENTITY_ENABLED", "true")
	t.Setenv("HELIUS_API_KEY", "")

	address := "Wallet6666666666666666666666666666666666666"
	_, calls := useHeliusIdentityTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"address": address, "type": "protocol", "name": "Known Entity", "category": "Protocol"},
		})
	}))

	if label := ResolveWalletLabel(t.Context(), "https://example.invalid", address); label != nil {
		t.Fatalf("missing provider key returned a label: %#v", label)
	}
	if *calls != 0 {
		t.Fatalf("missing provider key made %d requests", *calls)
	}

	t.Setenv("HELIUS_API_KEY", "paid-plan-key")
	label := ResolveWalletLabel(t.Context(), "https://example.invalid", address)
	if label == nil || label.Entity != "Known Entity" {
		t.Fatalf("provider configuration recovery was blocked by a false negative cache: %#v", label)
	}
	if *calls != 1 {
		t.Fatalf("expected one request after key became available, got %d", *calls)
	}
}

func TestHeliusWalletIdentityProviderFailureIsRetryable(t *testing.T) {
	resetHeliusWalletIdentityStateForTest()
	t.Cleanup(resetHeliusWalletIdentityStateForTest)
	t.Setenv("HELIUS_WALLET_IDENTITY_ENABLED", "true")
	t.Setenv("HELIUS_API_KEY", "paid-plan-key")

	address := "Wallet7777777777777777777777777777777777777"
	attempt := 0
	_, calls := useHeliusIdentityTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"address": address, "type": "exchange", "name": "Recovered Entity", "category": "Centralized Exchange"},
		})
	}))

	if label := ResolveWalletLabel(t.Context(), "", address); label != nil {
		t.Fatalf("provider failure unexpectedly returned a label: %#v", label)
	}
	label := ResolveWalletLabel(t.Context(), "", address)
	if label == nil || label.Entity != "Recovered Entity" {
		t.Fatalf("retry did not recover identity: %#v", label)
	}
	if *calls != 2 {
		t.Fatalf("expected retry after transient provider failure, got %d requests", *calls)
	}
}
