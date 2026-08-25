package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type heliusProgramAccountsV2RewriteTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (transport heliusProgramAccountsV2RewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.URL.Scheme = transport.target.Scheme
	clone.URL.Host = transport.target.Host
	return transport.base.RoundTrip(clone)
}

func heliusProgramAccountsV2TestClient(t *testing.T, handler http.Handler) *http.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: heliusProgramAccountsV2RewriteTransport{target: target, base: server.Client().Transport}}
}

func TestHeliusProgramAccountsV2SkipsNonHeliusProvider(t *testing.T) {
	t.Setenv("HELIUS_PROGRAM_ACCOUNTS_V2_ENABLED", "")
	handled, err := (&Handler{}).tryHeliusProgramAccountsV2(
		t.Context(),
		http.DefaultClient,
		"https://api.mainnet-beta.solana.com",
		"solana-mainnet",
		"getProgramAccounts",
		[]any{"Program1111111111111111111111111111111111", map[string]any{"withContext": true}},
		&struct{}{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if handled {
		t.Fatal("non-Helius RPC must retain standard getProgramAccounts")
	}
}

func TestHeliusProgramAccountsV2CanBeDisabledAsEmergencyFallback(t *testing.T) {
	t.Setenv("HELIUS_PROGRAM_ACCOUNTS_V2_ENABLED", "false")
	handled, err := (&Handler{}).tryHeliusProgramAccountsV2(
		t.Context(),
		http.DefaultClient,
		"https://mainnet.helius-rpc.com/?api-key=secret",
		"solana-mainnet",
		"getProgramAccounts",
		[]any{"Program1111111111111111111111111111111111", map[string]any{"withContext": true}},
		&struct{}{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if handled {
		t.Fatal("explicit Helius V2 kill switch must retain the standard RPC path")
	}
}

func TestHeliusProgramAccountsV2PaginatesUntilNullCursor(t *testing.T) {
	t.Setenv("HELIUS_PROGRAM_ACCOUNTS_V2_ENABLED", "true")
	calls := 0
	client := heliusProgramAccountsV2TestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var request struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Method != "getProgramAccountsV2" {
			t.Fatalf("unexpected method %q", request.Method)
		}
		if len(request.Params) != 2 {
			t.Fatalf("unexpected params: %#v", request.Params)
		}
		var config map[string]any
		if err := json.Unmarshal(request.Params[1], &config); err != nil {
			t.Fatal(err)
		}
		if got := int(config["limit"].(float64)); got != heliusProgramAccountsV2PageLimit {
			t.Fatalf("unexpected page limit %d", got)
		}
		if config["withContext"] != true {
			t.Fatal("withContext was not preserved")
		}
		if _, ok := config["filters"]; !ok {
			t.Fatal("filters were not preserved")
		}

		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			if _, ok := config["paginationKey"]; ok {
				t.Fatal("first page must not send a pagination key")
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":500,"apiVersion":"3.1.9"},"value":{"accounts":[{"pubkey":"AccountA","account":{"owner":"OwnerA","data":["","base64"]}}],"paginationKey":"cursor-1"}}}`))
			return
		}
		if config["paginationKey"] != "cursor-1" {
			t.Fatalf("second page did not use prior cursor: %#v", config["paginationKey"])
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":500,"apiVersion":"3.1.9"},"value":{"accounts":[{"pubkey":"AccountB","account":{"owner":"OwnerB","data":["","base64"]}}],"paginationKey":null}}}`))
	}))

	var out struct {
		Context struct {
			Slot uint64 `json:"slot"`
		} `json:"context"`
		Value []struct {
			Pubkey string `json:"pubkey"`
		} `json:"value"`
	}
	params := []any{
		"Program1111111111111111111111111111111111",
		map[string]any{
			"encoding":    "base64",
			"withContext": true,
			"filters":     []any{map[string]any{"dataSize": 241}},
		},
	}
	handled, err := (&Handler{}).tryHeliusProgramAccountsV2(
		t.Context(), client, "https://mainnet.helius-rpc.com/?api-key=secret", "solana-mainnet", "getProgramAccounts", params, &out,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !handled {
		t.Fatal("Helius provider should use getProgramAccountsV2")
	}
	if calls != 2 {
		t.Fatalf("expected two pages despite the short first page, got %d", calls)
	}
	if out.Context.Slot != 500 {
		t.Fatalf("unexpected normalized context slot %d", out.Context.Slot)
	}
	if len(out.Value) != 2 || out.Value[0].Pubkey != "AccountA" || out.Value[1].Pubkey != "AccountB" {
		t.Fatalf("unexpected normalized accounts: %#v", out.Value)
	}
}

func TestHeliusProgramAccountsV2RejectsCrossPageContextDrift(t *testing.T) {
	t.Setenv("HELIUS_PROGRAM_ACCOUNTS_V2_ENABLED", "true")
	calls := 0
	client := heliusProgramAccountsV2TestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":700},"value":{"accounts":[],"paginationKey":"cursor-2"}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":701},"value":{"accounts":[],"paginationKey":null}}}`))
	}))

	var out struct {
		Context struct {
			Slot uint64 `json:"slot"`
		} `json:"context"`
		Value []json.RawMessage `json:"value"`
	}
	handled, err := (&Handler{}).tryHeliusProgramAccountsV2(
		t.Context(),
		client,
		"https://mainnet.helius-rpc.com/?api-key=secret",
		"solana-mainnet",
		"getProgramAccounts",
		[]any{"Program1111111111111111111111111111111111", map[string]any{"withContext": true}},
		&out,
	)
	if !handled {
		t.Fatal("Helius provider should be handled")
	}
	if err == nil || !strings.Contains(err.Error(), "context slot changed across pages") {
		t.Fatalf("expected context-drift failure, got %v", err)
	}
	if out.Context.Slot != 0 || len(out.Value) != 0 {
		t.Fatalf("partial cross-slot evidence must not be normalized into the caller target: %#v", out)
	}
}

func TestHeliusProgramAccountsV2NormalizesWithoutContext(t *testing.T) {
	t.Setenv("HELIUS_PROGRAM_ACCOUNTS_V2_ENABLED", "true")
	client := heliusProgramAccountsV2TestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"accounts":[{"pubkey":"AccountC"}],"paginationKey":null}}`))
	}))
	var out []struct {
		Pubkey string `json:"pubkey"`
	}
	handled, err := (&Handler{}).tryHeliusProgramAccountsV2(
		t.Context(),
		client,
		"https://mainnet.helius-rpc.com/?api-key=secret",
		"solana-mainnet",
		"getProgramAccounts",
		[]any{"Program1111111111111111111111111111111111", map[string]any{"encoding": "base64"}},
		&out,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !handled || len(out) != 1 || out[0].Pubkey != "AccountC" {
		t.Fatalf("unexpected context-free normalized result: handled=%v out=%#v", handled, out)
	}
}
