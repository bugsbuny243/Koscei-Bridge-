package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type createdMintRewriteTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (transport createdMintRewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.URL.Scheme = transport.target.Scheme
	clone.URL.Host = transport.target.Host
	return transport.base.RoundTrip(clone)
}

func TestFetchHeliusCreatedMintDiscoveryDefaultsToStandardRPC(t *testing.T) {
	methodCalls := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		methodCalls[payload.Method]++
		w.Header().Set("Content-Type", "application/json")
		switch payload.Method {
		case "getSignaturesForAddress":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": []any{
					map[string]any{"signature": "SigCreate", "slot": 101, "err": nil, "blockTime": 1700000001},
					map[string]any{"signature": "SigOther", "slot": 100, "err": nil, "blockTime": 1700000000},
				},
			})
		case "getTransaction":
			signature, _ := payload.Params[0].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": createdMintTestTransaction(signature, signature == "SigCreate"),
			})
		default:
			t.Fatalf("unexpected standard RPC method %q", payload.Method)
		}
	}))
	defer server.Close()

	previousRPCClient := solanaRPCClient
	solanaRPCClient = server.Client()
	t.Cleanup(func() { solanaRPCClient = previousRPCClient })
	resetSolanaRPCCachesForTest()
	resetSolanaRPCBatchCircuitForTest()
	resetSolanaRPCBatchModeCacheForTest()
	t.Setenv("KOSCHEI_HELIUS_CREATED_MINT_GTFA_ENABLED", "")
	t.Setenv("HELIUS_API_KEY", "configured-but-not-used")
	t.Setenv("SOLANA_RPC_BATCH_ENABLED", "false")
	t.Setenv("SOLANA_RPC_MIN_INTERVAL_MS", "0")
	t.Setenv("SOLANA_CREATED_MINT_MAX_PAGES", "1")
	t.Setenv("SOLANA_CREATED_MINT_PAGE_LIMIT", "25")
	t.Setenv("SOLANA_CREATED_MINT_TX_LIMIT", "10")

	out := FetchHeliusCreatedMintDiscovery(t.Context(), server.URL, "Actor111")
	if !out.Available || out.Provider != standardRPCCreatedMintProvider {
		t.Fatalf("expected standard RPC discovery, got %#v", out)
	}
	if out.Status != "complete" {
		t.Fatalf("expected complete bounded-window coverage for exhausted 2-signature history, got %q", out.Status)
	}
	if len(out.Candidates) != 1 || out.Candidates[0].Mint != "Mint111" || out.Candidates[0].Signature != "SigCreate" {
		t.Fatalf("created mint not extracted from standard RPC: %#v", out.Candidates)
	}
	if methodCalls["getTransactionsForAddress"] != 0 {
		t.Fatalf("paid getTransactionsForAddress must not run without explicit opt-in: %#v", methodCalls)
	}
}

func TestFetchHeliusCreatedMintDiscoveryFallsBackFromUnavailableGTFA(t *testing.T) {
	gtfaCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]any
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		method, _ := raw["method"].(string)
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "getTransactionsForAddress":
			gtfaCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"error": map[string]any{"code": -32000, "message": "Developer plan required"},
			})
		case "getSignaturesForAddress":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": []any{map[string]any{"signature": "SigCreate", "slot": 101, "err": nil, "blockTime": 1700000001}},
			})
		case "getTransaction":
			params, _ := raw["params"].([]any)
			signature, _ := params[0].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": createdMintTestTransaction(signature, true),
			})
		default:
			t.Fatalf("unexpected method %q", method)
		}
	}))
	defer server.Close()

	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	previousDefaultClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: createdMintRewriteTransport{target: target, base: server.Client().Transport}}
	t.Cleanup(func() { http.DefaultClient = previousDefaultClient })
	previousRPCClient := solanaRPCClient
	solanaRPCClient = server.Client()
	t.Cleanup(func() { solanaRPCClient = previousRPCClient })
	resetSolanaRPCCachesForTest()
	resetSolanaRPCBatchCircuitForTest()
	resetSolanaRPCBatchModeCacheForTest()
	t.Setenv("KOSCHEI_HELIUS_CREATED_MINT_GTFA_ENABLED", "true")
	t.Setenv("HELIUS_API_KEY", "test-key")
	t.Setenv("HELIUS_CREATED_MINT_PAGE_DELAY_MS", "0")
	t.Setenv("SOLANA_RPC_BATCH_ENABLED", "false")
	t.Setenv("SOLANA_RPC_MIN_INTERVAL_MS", "0")
	t.Setenv("SOLANA_CREATED_MINT_MAX_PAGES", "1")
	t.Setenv("SOLANA_CREATED_MINT_PAGE_LIMIT", "25")
	t.Setenv("SOLANA_CREATED_MINT_TX_LIMIT", "10")

	out := FetchHeliusCreatedMintDiscovery(t.Context(), server.URL, "Actor111")
	if gtfaCalls != 1 {
		t.Fatalf("expected one opted-in gTFA attempt, got %d", gtfaCalls)
	}
	if !out.Available || out.Provider != standardRPCCreatedMintProvider || len(out.Candidates) != 1 {
		t.Fatalf("expected standard RPC fallback after gTFA rejection, got %#v", out)
	}
	joined := strings.Join(out.Limitations, " ")
	if !strings.Contains(joined, "standard RPC fallback was used") || !strings.Contains(joined, "Developer plan required") {
		t.Fatalf("fallback reason must remain explainable, got %q", joined)
	}
}

func TestSelectCreatedMintSignatureSampleSpansObservedWindow(t *testing.T) {
	rows := make([]SolanaSignatureInfo, 10)
	for index := range rows {
		rows[index] = SolanaSignatureInfo{Signature: "Sig" + string(rune('0'+index))}
	}
	selected := selectCreatedMintSignatureSample(rows, 4)
	if len(selected) != 4 {
		t.Fatalf("expected four sampled signatures, got %d", len(selected))
	}
	if selected[0].Signature != rows[0].Signature || selected[len(selected)-1].Signature != rows[len(rows)-1].Signature {
		t.Fatalf("sample must preserve newest and oldest observed edges: %#v", selected)
	}
}

func TestHeliusCreatedMintGTFAOptInParserIsExplicit(t *testing.T) {
	for _, value := range []string{"true", "TRUE", "1", "yes", "on"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("KOSCHEI_HELIUS_CREATED_MINT_GTFA_ENABLED", value)
			if !heliusCreatedMintGTFAEnabled() {
				t.Fatalf("expected %q to enable paid gTFA discovery", value)
			}
		})
	}
	for _, value := range []string{"", "false", "0", "no", "off", "unexpected"} {
		t.Run("disabled_"+value, func(t *testing.T) {
			t.Setenv("KOSCHEI_HELIUS_CREATED_MINT_GTFA_ENABLED", value)
			if heliusCreatedMintGTFAEnabled() {
				t.Fatalf("expected %q to keep paid gTFA discovery disabled", value)
			}
		})
	}
}

func createdMintTestTransaction(signature string, withMint bool) map[string]any {
	instructions := []any{map[string]any{
		"programId": "11111111111111111111111111111111",
		"parsed": map[string]any{"type": "transfer", "info": map[string]any{}},
	}}
	if withMint {
		instructions = []any{map[string]any{
			"programId": canonicalSPLTokenProgramID,
			"program":   "spl-token",
			"parsed": map[string]any{
				"type": "initializeMint",
				"info": map[string]any{"mint": "Mint111"},
			},
		}}
	}
	return map[string]any{
		"slot":      101,
		"blockTime": 1700000001,
		"transaction": map[string]any{
			"signatures": []any{signature},
			"message": map[string]any{
				"accountKeys": []any{
					map[string]any{"pubkey": "Actor111", "signer": true},
					map[string]any{"pubkey": "Mint111", "signer": false},
				},
				"instructions": instructions,
			},
		},
		"meta": map[string]any{"err": nil},
	}
}
