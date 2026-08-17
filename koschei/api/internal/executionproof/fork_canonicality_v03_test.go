package executionproof

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func canonicalityRPCServer(t *testing.T, chainID, blockHash, head string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var req struct { ID int `json:"id"`; Method string `json:"method"` }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { t.Fatal(err) }
		var result any
		switch req.Method {
		case "eth_chainId": result = chainID
		case "eth_getBlockByNumber": result = map[string]any{"hash":blockHash}
		case "eth_blockNumber": result = head
		default: t.Fatalf("unexpected method %q",req.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc":"2.0","id":req.ID,"result":result})
	}))
}

func TestRPCForkCanonicalityVerifierPassesCanonicalFreshBlock(t *testing.T) {
	hash := "0x"+strings.Repeat("a",64)
	server := canonicalityRPCServer(t,"0x1",hash,"0x69"); defer server.Close()
	v := RPCForkCanonicalityVerifier{RPCURL:server.URL,MaxHeadLag:5}
	if err := v.VerifyCanonical(context.Background(),1,100,hash); err != nil { t.Fatal(err) }
}

func TestRPCForkCanonicalityVerifierRejectsReorgedBlock(t *testing.T) {
	hash := "0x"+strings.Repeat("a",64)
	server := canonicalityRPCServer(t,"0x1","0x"+strings.Repeat("b",64),"0x69"); defer server.Close()
	v := RPCForkCanonicalityVerifier{RPCURL:server.URL,MaxHeadLag:5}
	if err := v.VerifyCanonical(context.Background(),1,100,hash); err == nil { t.Fatal("reorged block accepted") }
}

func TestRPCForkCanonicalityVerifierRejectsStaleReference(t *testing.T) {
	hash := "0x"+strings.Repeat("a",64)
	server := canonicalityRPCServer(t,"0x1",hash,"0x70"); defer server.Close()
	v := RPCForkCanonicalityVerifier{RPCURL:server.URL,MaxHeadLag:5}
	if err := v.VerifyCanonical(context.Background(),1,100,hash); err == nil { t.Fatal("stale reference block accepted") }
}
