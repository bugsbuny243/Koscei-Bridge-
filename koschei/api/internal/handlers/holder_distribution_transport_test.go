package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHolderDistributionTransportUsesOnlySolanaRPCProof(t *testing.T) {
	calls := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var request struct {
			ID     int             `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		calls[request.Method]++
		w.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case "getTokenSupply":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"value":{"amount":"1000","decimals":0,"uiAmount":1000,"uiAmountString":"1000"}}}`))
		case "getTokenLargestAccounts":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"value":[{"address":"TokenAccountA","amount":"500","decimals":0,"uiAmount":500,"uiAmountString":"500"},{"address":"TokenAccountB","amount":"300","decimals":0,"uiAmount":300,"uiAmountString":"300"}]}}`))
		case "getMultipleAccounts":
			var params []any
			_ = json.Unmarshal(request.Params, &params)
			addresses, _ := params[0].([]any)
			if len(addresses) > 0 && addresses[0] == "TokenAccountA" {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":123},"value":[{"data":{"parsed":{"info":{"owner":"WalletA"}}},"executable":false,"owner":"TokenProgram111"},{"data":{"parsed":{"info":{"owner":"1nc1nerator11111111111111111111111111111111"}}},"executable":false,"owner":"TokenProgram111"}]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":124},"value":[{"data":{},"executable":false,"owner":"11111111111111111111111111111111"},{"data":{},"executable":false,"owner":"11111111111111111111111111111111"}]}}`))
		default:
			http.Error(w, "unexpected method", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	t.Setenv("SOLANA_RPC_URL", server.URL)
	// Prove an available Helius credential cannot become a prerequisite or add
	// identity network calls to the critical holder proof path.
	t.Setenv("HELIUS_API_KEY", "must-not-be-used-by-holder-core")
	t.Setenv("ALCHEMY_API_KEY", "")

	h := &Handler{}
	distribution, roles := h.radarDetailHolderDistributionTransport(t.Context(), "Mint111", "solana-mainnet")
	if !roles.Available {
		t.Fatalf("expected holder roles from Solana snapshot: %#v", roles)
	}
	if got := distribution["transport"]; got != "koschei_rpc_manager" {
		t.Fatalf("unexpected transport marker: %#v", got)
	}
	if got := distribution["identity_enrichment_required_for_holder_verdict"]; got != false {
		t.Fatalf("third-party identity must not gate holder verdict: %#v", got)
	}
	if calls["getTokenSupply"] != 1 || calls["getTokenLargestAccounts"] != 1 || calls["getMultipleAccounts"] != 2 {
		t.Fatalf("unexpected RPC call set: %#v", calls)
	}
	if roles.RawTop1Percentage != 50 || roles.BurnPercentage != 30 {
		t.Fatalf("unexpected holder analysis: %#v", roles)
	}
}
