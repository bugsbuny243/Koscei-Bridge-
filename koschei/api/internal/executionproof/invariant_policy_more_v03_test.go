package executionproof

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func storageRPCServer(t *testing.T, value string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var req struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Method != "eth_getStorageAt" {
			t.Fatalf("unexpected rpc method %q", req.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": value})
	}))
}

func TestPolicyBoundPrivilegedRolePassesExpectedStorage(t *testing.T) {
	policy := PrivilegedRolePolicy{Contract: "0x1111111111111111111111111111111111111111", StorageSlot: "0x" + strings.Repeat("0", 64), ExpectedValue: "0x" + strings.Repeat("a", 64)}
	digest, ok := PrivilegedRolePolicyDigest(policy)
	if !ok {
		t.Fatal("digest")
	}
	server := storageRPCServer(t, policy.ExpectedValue)
	defer server.Close()
	registry := StaticInvariantPolicyRegistry{PrivilegedRole: map[string]PrivilegedRolePolicy{digest: policy}}
	checks, err := (PolicyBoundInvariantEvaluator{Registry: registry}).EvaluatePostState(context.Background(), server.URL, PreparedVerifiedForkRequest{Invariants: []ApprovedInvariantDefinition{{ID: "admin-slot", Class: InvariantPrivilegedRole, ParametersSHA256: digest}}}, "0x"+strings.Repeat("3", 64))
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 || !checks[0].Passed || !validSHA256(checks[0].Evidence) {
		t.Fatalf("unexpected checks %#v", checks)
	}
}

func TestPolicyBoundPrivilegedRoleFailsChangedStorage(t *testing.T) {
	policy := PrivilegedRolePolicy{Contract: "0x1111111111111111111111111111111111111111", StorageSlot: "0x" + strings.Repeat("0", 64), ExpectedValue: "0x" + strings.Repeat("a", 64)}
	digest, _ := PrivilegedRolePolicyDigest(policy)
	server := storageRPCServer(t, "0x"+strings.Repeat("b", 64))
	defer server.Close()
	registry := StaticInvariantPolicyRegistry{PrivilegedRole: map[string]PrivilegedRolePolicy{digest: policy}}
	checks, err := (PolicyBoundInvariantEvaluator{Registry: registry}).EvaluatePostState(context.Background(), server.URL, PreparedVerifiedForkRequest{Invariants: []ApprovedInvariantDefinition{{ID: "admin-slot", Class: InvariantPrivilegedRole, ParametersSHA256: digest}}}, "0x"+strings.Repeat("3", 64))
	if err != nil {
		t.Fatal(err)
	}
	if checks[0].Passed {
		t.Fatal("changed privileged role passed")
	}
}

func TestPolicyBoundTreasuryBoundPassesAtLimit(t *testing.T) {
	policy := TreasuryBoundPolicy{Target: "0x2222222222222222222222222222222222222222", MaxValueWei: "0x64"}
	digest, ok := TreasuryBoundPolicyDigest(policy)
	if !ok {
		t.Fatal("digest")
	}
	registry := StaticInvariantPolicyRegistry{TreasuryBound: map[string]TreasuryBoundPolicy{digest: policy}}
	checks, err := (PolicyBoundInvariantEvaluator{Registry: registry}).EvaluatePostState(context.Background(), "http://unused", PreparedVerifiedForkRequest{Payload: EVMPayload{From: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", To: policy.Target, ValueHex: "0x64", DataHex: "0x"}, Invariants: []ApprovedInvariantDefinition{{ID: "treasury-cap", Class: InvariantTreasuryBound, ParametersSHA256: digest}}}, "0x"+strings.Repeat("3", 64))
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 || !checks[0].Passed {
		t.Fatalf("unexpected checks %#v", checks)
	}
}

func TestPolicyBoundTreasuryBoundFailsAboveLimit(t *testing.T) {
	policy := TreasuryBoundPolicy{Target: "0x2222222222222222222222222222222222222222", MaxValueWei: "0x64"}
	digest, _ := TreasuryBoundPolicyDigest(policy)
	registry := StaticInvariantPolicyRegistry{TreasuryBound: map[string]TreasuryBoundPolicy{digest: policy}}
	checks, err := (PolicyBoundInvariantEvaluator{Registry: registry}).EvaluatePostState(context.Background(), "http://unused", PreparedVerifiedForkRequest{Payload: EVMPayload{From: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", To: policy.Target, ValueHex: "0x65", DataHex: "0x"}, Invariants: []ApprovedInvariantDefinition{{ID: "treasury-cap", Class: InvariantTreasuryBound, ParametersSHA256: digest}}}, "0x"+strings.Repeat("3", 64))
	if err != nil {
		t.Fatal(err)
	}
	if checks[0].Passed {
		t.Fatal("treasury value above limit passed")
	}
}
