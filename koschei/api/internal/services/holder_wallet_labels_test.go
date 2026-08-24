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
	heliusIdentityHTTPClient = &http.Client{
		Transport: heliusIdentityRewriteTransport{target: target, base: server.Client().Transport},
	}
	return server, &calls
}

func TestHeliusWalletIdentityDisabledByDefault(t *testing.T) {
	resetHeliusWalletIdentityStateForTest()
	t.Cleanup(resetHeliusWalletIdentityStateForTest)
	t.Setenv("HELIUS_WALLET_IDENTITY_ENABLED", "")
	t.Setenv("HELIUS_API_KEY", "configured-key")

	_, calls := useHeliusIdentityTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	if label := ResolveWalletLabel(t.Context(), "", "Wallet1111111111111111111111111111111111111"); label != nil {
		t.Fatalf("disabled wallet identity returned a label: %#v", label)
	}
	if *calls != 0 {
		t.Fatalf("disabled wallet identity made %d provider calls", *calls)
	}
}

func TestHeliusWalletIdentity403TripsProcessCapabilityCircuit(t *testing.T) {
	resetHeliusWalletIdentityStateForTest()
	t.Cleanup(resetHeliusWalletIdentityStateForTest)
	t.Setenv("HELIUS_WALLET_IDENTITY_ENABLED", "true")
	t.Setenv("HELIUS_API_KEY", "free-plan-key")

	_, calls := useHeliusIdentityTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))

	if label := ResolveWalletLabel(t.Context(), "", "Wallet1111111111111111111111111111111111111"); label != nil {
		t.Fatalf("403 response returned a label: %#v", label)
	}
	if label := ResolveWalletLabel(t.Context(), "", "Wallet2222222222222222222222222222222222222"); label != nil {
		t.Fatalf("capability-disabled response returned a label: %#v", label)
	}
	if *calls != 1 {
		t.Fatalf("expected one provider call before the 403 circuit opened, got %d", *calls)
	}
	if !heliusWalletIdentityUnavailable() {
		t.Fatal("expected wallet identity capability circuit to be unavailable after 403")
	}
}

func TestHeliusWalletIdentity404NegativeCachesOnlyThatAddress(t *testing.T) {
	resetHeliusWalletIdentityStateForTest()
	t.Cleanup(resetHeliusWalletIdentityStateForTest)
	t.Setenv("HELIUS_WALLET_IDENTITY_ENABLED", "1")
	t.Setenv("HELIUS_API_KEY", "paid-plan-key")

	_, calls := useHeliusIdentityTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	address := "Wallet3333333333333333333333333333333333333"
	if label := ResolveWalletLabel(t.Context(), "", address); label != nil {
		t.Fatalf("404 response returned a label: %#v", label)
	}
	if label := ResolveWalletLabel(t.Context(), "", address); label != nil {
		t.Fatalf("cached 404 returned a label: %#v", label)
	}
	if *calls != 1 {
		t.Fatalf("expected definitive 404 to be cached per address, got %d calls", *calls)
	}
	if heliusWalletIdentityUnavailable() {
		t.Fatal("404 must not disable the provider capability")
	}
}

func TestHeliusWalletIdentityPositiveResultIsCached(t *testing.T) {
	resetHeliusWalletIdentityStateForTest()
	t.Cleanup(resetHeliusWalletIdentityStateForTest)
	t.Setenv("HELIUS_WALLET_IDENTITY_ENABLED", "yes")
	t.Setenv("HELIUS_API_KEY", "paid-plan-key")

	_, calls := useHeliusIdentityTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "Binance Hot Wallet", "entity": "Binance", "category": "CEX",
			"labels": []string{"exchange"}, "tags": []string{"custodial"},
		})
	}))

	address := "Wallet4444444444444444444444444444444444444"
	first := ResolveWalletLabel(t.Context(), "", address)
	second := ResolveWalletLabel(t.Context(), "", address)
	if first == nil || second == nil {
		t.Fatalf("expected positive wallet label, got first=%#v second=%#v", first, second)
	}
	if first.Entity != "Binance" || first.Category != "CEX" || first.Source != "helius_identity" {
		t.Fatalf("unexpected wallet label: %#v", first)
	}
	if *calls != 1 {
		t.Fatalf("expected positive identity result to be cached, got %d calls", *calls)
	}
}

func TestHeliusWalletIdentityMissingKeyIsNotCachedAsUnlabeled(t *testing.T) {
	resetHeliusWalletIdentityStateForTest()
	t.Cleanup(resetHeliusWalletIdentityStateForTest)
	t.Setenv("HELIUS_WALLET_IDENTITY_ENABLED", "on")
	t.Setenv("HELIUS_API_KEY", "")

	_, calls := useHeliusIdentityTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"entity": "Known Entity", "category": "PROTOCOL"})
	}))

	address := "Wallet5555555555555555555555555555555555555"
	if label := ResolveWalletLabel(t.Context(), "https://example.invalid", address); label != nil {
		t.Fatalf("missing provider key returned a label: %#v", label)
	}
	if *calls != 0 {
		t.Fatalf("missing provider key made %d calls", *calls)
	}

	t.Setenv("HELIUS_API_KEY", "paid-plan-key")
	label := ResolveWalletLabel(t.Context(), "https://example.invalid", address)
	if label == nil || label.Entity != "Known Entity" {
		t.Fatalf("provider configuration recovery was blocked by a false negative cache: %#v", label)
	}
	if *calls != 1 {
		t.Fatalf("expected one provider call after key became available, got %d", *calls)
	}
}
