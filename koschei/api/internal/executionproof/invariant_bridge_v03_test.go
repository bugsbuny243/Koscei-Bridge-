package executionproof

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func bridgeRPCServer(t *testing.T, reserveHex, supplyHex string) *httptest.Server {
	t.Helper()
	var calls atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var req struct { ID int `json:"id"`; Method string `json:"method"` }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { t.Fatal(err) }
		if req.Method != "eth_call" { t.Fatalf("unexpected method %q", req.Method) }
		result := reserveHex
		if calls.Add(1) == 2 { result = supplyHex }
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc":"2.0","id":req.ID,"result":result})
	}))
}

func bridgePolicyFixture() BridgeReservePolicy {
	return BridgeReservePolicy{
		ReserveProbe: BridgeReadProbe{Contract:"0x1111111111111111111111111111111111111111", DataHex:"0x12345678"},
		SupplyProbe: BridgeReadProbe{Contract:"0x2222222222222222222222222222222222222222", DataHex:"0x18160ddd"},
	}
}

func TestBridgeReserveSupplyPassesWhenReserveCoversSupply(t *testing.T) {
	policy := bridgePolicyFixture(); digest,ok := BridgeReservePolicyDigest(policy); if !ok { t.Fatal("digest") }
	server := bridgeRPCServer(t,"0x64","0x63"); defer server.Close()
	registry := StaticInvariantPolicyRegistry{BridgeReserve:map[string]BridgeReservePolicy{digest:policy}}
	checks,err := (PolicyBoundInvariantEvaluator{Registry:registry}).EvaluatePostState(context.Background(),server.URL,PreparedVerifiedForkRequest{Invariants:[]ApprovedInvariantDefinition{{ID:"bridge-solvency",Class:InvariantBridgeReserve,ParametersSHA256:digest}}},"0x"+strings.Repeat("3",64))
	if err != nil { t.Fatal(err) }
	if len(checks)!=1 || !checks[0].Passed || !validSHA256(checks[0].Evidence) { t.Fatalf("unexpected checks %#v",checks) }
}

func TestBridgeReserveSupplyFailsWhenSupplyExceedsReserve(t *testing.T) {
	policy := bridgePolicyFixture(); digest,_ := BridgeReservePolicyDigest(policy)
	server := bridgeRPCServer(t,"0x63","0x64"); defer server.Close()
	registry := StaticInvariantPolicyRegistry{BridgeReserve:map[string]BridgeReservePolicy{digest:policy}}
	checks,err := (PolicyBoundInvariantEvaluator{Registry:registry}).EvaluatePostState(context.Background(),server.URL,PreparedVerifiedForkRequest{Invariants:[]ApprovedInvariantDefinition{{ID:"bridge-solvency",Class:InvariantBridgeReserve,ParametersSHA256:digest}}},"0x"+strings.Repeat("3",64))
	if err != nil { t.Fatal(err) }
	if checks[0].Passed { t.Fatal("insolvent bridge passed") }
}

func TestBridgeReserveSupplyRejectsUnknownPolicy(t *testing.T) {
	server := bridgeRPCServer(t,"0x64","0x63"); defer server.Close()
	registry := StaticInvariantPolicyRegistry{BridgeReserve:map[string]BridgeReservePolicy{}}
	_,err := (PolicyBoundInvariantEvaluator{Registry:registry}).EvaluatePostState(context.Background(),server.URL,PreparedVerifiedForkRequest{Invariants:[]ApprovedInvariantDefinition{{ID:"bridge-solvency",Class:InvariantBridgeReserve,ParametersSHA256:strings.Repeat("9",64)}}},"0x"+strings.Repeat("3",64))
	if err == nil { t.Fatal("unknown bridge policy accepted") }
}
