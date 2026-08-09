package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestTrustedJupiterGETJSONDoesNotLeakKeyToCustomHost(t *testing.T) {
	t.Setenv("JUPITER_API_KEY", "unit-test")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "" {
			http.Error(w, "Jupiter key leaked", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer server.Close()
	var body map[string]any
	if err := trustedJupiterGETJSON(context.Background(), server.Client(), server.URL+"/price", &body); err != nil {
		t.Fatal(err)
	}
	if body["ok"] != true {
		t.Fatalf("unexpected body: %#v", body)
	}
}

func TestTrustedJupiterGETJSONFailsBeforeOfficialHTTPWithoutKey(t *testing.T) {
	t.Setenv("JUPITER_API_KEY", "")
	var called atomic.Bool
	client := &http.Client{Transport: exitLiquidityRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		called.Store(true)
		t.Fatal("official Jupiter transport should not run without a key")
		return nil, nil
	})}
	var body map[string]any
	err := trustedJupiterGETJSON(context.Background(), client, "https://api.jup.ag/price/v3?ids=Mint", &body)
	if err != errJupiterAPIKeyUnavailable {
		t.Fatalf("err=%v want errJupiterAPIKeyUnavailable", err)
	}
	if called.Load() {
		t.Fatal("missing key reached official Jupiter transport")
	}
}

func TestTrustedJupiterGETJSONSendsKeyOnlyToExactOfficialHost(t *testing.T) {
	t.Setenv("JUPITER_API_KEY", "unit-test")
	client := &http.Client{Transport: exitLiquidityRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Hostname() != "api.jup.ag" {
			t.Fatalf("host=%q", request.URL.Hostname())
		}
		if request.Header.Get("x-api-key") != "unit-test" {
			t.Fatal("official Jupiter request did not receive key")
		}
		body := `{"ok":true}`
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: ioNopCloserString(body), Request: request}, nil
	})}
	var body map[string]any
	if err := trustedJupiterGETJSON(context.Background(), client, "https://api.jup.ag/price/v3?ids=Mint", &body); err != nil {
		t.Fatal(err)
	}
}

func TestJupiterAPIKeyHelperRejectsLookalikeHostForMarketContext(t *testing.T) {
	t.Setenv("JUPITER_API_KEY", "unit-test")
	for _, endpoint := range []string{
		"https://api.jup.ag.evil.example/price/v3",
		"https://jup.example/price/v3",
		"http://localhost/price",
	} {
		if got := jupiterAPIKeyForQuoteEndpoint(endpoint); got != "" {
			t.Fatalf("key leaked to %q", endpoint)
		}
	}
}

func TestValidatedReadOnlyJupiterPriceEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"https://api.jup.ag/price/v3",
		"http://localhost/price",
	} {
		if _, err := validatedReadOnlyJupiterPriceEndpoint(endpoint); err != nil {
			t.Fatalf("valid endpoint %q rejected: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{
		"https://api.jup.ag/swap/v2/order",
		"http://example.com/price",
	} {
		if _, err := validatedReadOnlyJupiterPriceEndpoint(endpoint); err == nil {
			t.Fatalf("unsafe/non-price endpoint %q accepted", endpoint)
		}
	}
}

func ioNopCloserString(value string) *stringReadCloser {
	return &stringReadCloser{Reader: strings.NewReader(value)}
}

type stringReadCloser struct {
	*strings.Reader
}

func (r *stringReadCloser) Close() error { return nil }
