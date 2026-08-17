package executionproof

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func proxyCodeRPCServer(t *testing.T, codeHex string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var req struct {
			JSONRPC string `json:"jsonrpc"`
			ID      int    `json:"id"`
			Method  string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode rpc request: %v", err)
		}
		if req.Method != "eth_getCode" {
			t.Fatalf("unexpected rpc method %q", req.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": codeHex})
	}))
}

func TestPolicyBoundInvariantEvaluatorPassesApprovedProxyCodehash(t *testing.T) {
	code := []byte{0x60, 0x00, 0x60, 0x00}
	policy := ProxyCodehashPolicy{
		Address:            "0x1111111111111111111111111111111111111111",
		ExpectedCodeSHA256: sha256Hex(code),
	}
	policyDigest, ok := ProxyCodehashPolicyDigest(policy)
	if !ok { t.Fatal("policy digest failed") }
	registry := StaticInvariantPolicyRegistry{ProxyCodehash: map[string]ProxyCodehashPolicy{policyDigest: policy}}
	server := proxyCodeRPCServer(t, "0x60006000")
	defer server.Close()

	evaluator := PolicyBoundInvariantEvaluator{Registry: registry}
	checks, err := evaluator.EvaluatePostState(context.Background(), server.URL, PreparedVerifiedForkRequest{
		Invariants: []ApprovedInvariantDefinition{{ID: "proxy-codehash", Class: InvariantProxyCodehash, ParametersSHA256: policyDigest}},
	}, "0x"+strings.Repeat("3", 64))
	if err != nil { t.Fatal(err) }
	if len(checks) != 1 || !checks[0].Passed || !validSHA256(checks[0].Evidence) {
		t.Fatalf("unexpected checks: %#v", checks)
	}
}

func TestPolicyBoundInvariantEvaluatorFailsChangedProxyCode(t *testing.T) {
	policy := ProxyCodehashPolicy{
		Address:            "0x1111111111111111111111111111111111111111",
		ExpectedCodeSHA256: sha256Hex([]byte{0x60, 0x00}),
	}
	policyDigest, _ := ProxyCodehashPolicyDigest(policy)
	registry := StaticInvariantPolicyRegistry{ProxyCodehash: map[string]ProxyCodehashPolicy{policyDigest: policy}}
	server := proxyCodeRPCServer(t, "0x6001")
	defer server.Close()

	checks, err := (PolicyBoundInvariantEvaluator{Registry: registry}).EvaluatePostState(context.Background(), server.URL, PreparedVerifiedForkRequest{
		Invariants: []ApprovedInvariantDefinition{{ID: "proxy-codehash", Class: InvariantProxyCodehash, ParametersSHA256: policyDigest}},
	}, "0x"+strings.Repeat("3", 64))
	if err != nil { t.Fatal(err) }
	if len(checks) != 1 || checks[0].Passed {
		t.Fatalf("changed proxy code incorrectly passed: %#v", checks)
	}
}

func TestPolicyBoundInvariantEvaluatorRejectsUnknownPolicyDigest(t *testing.T) {
	server := proxyCodeRPCServer(t, "0x6000")
	defer server.Close()
	evaluator := PolicyBoundInvariantEvaluator{Registry: StaticInvariantPolicyRegistry{ProxyCodehash: map[string]ProxyCodehashPolicy{}}}
	_, err := evaluator.EvaluatePostState(context.Background(), server.URL, PreparedVerifiedForkRequest{
		Invariants: []ApprovedInvariantDefinition{{ID: "proxy-codehash", Class: InvariantProxyCodehash, ParametersSHA256: strings.Repeat("9", 64)}},
	}, "0x"+strings.Repeat("3", 64))
	if err == nil { t.Fatal("unknown policy digest was accepted") }
}

func TestPolicyBoundInvariantEvaluatorRejectsUnsupportedInvariantClass(t *testing.T) {
	server := proxyCodeRPCServer(t, "0x6000")
	defer server.Close()
	evaluator := PolicyBoundInvariantEvaluator{Registry: StaticInvariantPolicyRegistry{ProxyCodehash: map[string]ProxyCodehashPolicy{}}}
	_, err := evaluator.EvaluatePostState(context.Background(), server.URL, PreparedVerifiedForkRequest{
		Invariants: []ApprovedInvariantDefinition{{ID: "supply", Class: InvariantAssetConservation, ParametersSHA256: strings.Repeat("1", 64)}},
	}, "0x"+strings.Repeat("3", 64))
	if err == nil { t.Fatal("unsupported invariant class was accepted") }
}
