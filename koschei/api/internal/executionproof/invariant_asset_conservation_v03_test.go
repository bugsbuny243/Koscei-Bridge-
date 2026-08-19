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

func conservationRPCServer(t *testing.T, values ...string) *httptest.Server {
	t.Helper()
	var calls atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var req struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Method != "eth_call" {
			t.Fatalf("unexpected method %q", req.Method)
		}
		i := int(calls.Add(1)) - 1
		if i >= len(values) {
			t.Fatalf("unexpected extra eth_call %d", i)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": values[i]})
	}))
}

func conservationPolicyFixture() AssetConservationPolicy {
	return AssetConservationPolicy{
		SupplyProbe: BridgeReadProbe{Contract: "0x1111111111111111111111111111111111111111", DataHex: "0x18160ddd"},
		AccountedProbes: []BridgeReadProbe{
			{Contract: "0x1111111111111111111111111111111111111111", DataHex: "0x70a08231000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			{Contract: "0x1111111111111111111111111111111111111111", DataHex: "0x70a08231000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		},
	}
}

func TestAssetConservationPassesExactAccounting(t *testing.T) {
	p := conservationPolicyFixture()
	d, ok := AssetConservationPolicyDigest(p)
	if !ok {
		t.Fatal("digest")
	}
	s := conservationRPCServer(t, "0x64", "0x28", "0x3c")
	defer s.Close()
	r := StaticInvariantPolicyRegistry{AssetConservation: map[string]AssetConservationPolicy{d: p}}
	checks, err := (PolicyBoundInvariantEvaluator{Registry: r}).EvaluatePostState(context.Background(), s.URL, PreparedVerifiedForkRequest{Invariants: []ApprovedInvariantDefinition{{ID: "asset-conservation", Class: InvariantAssetConservation, ParametersSHA256: d}}}, "0x"+strings.Repeat("3", 64))
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 || !checks[0].Passed || !validSHA256(checks[0].Evidence) {
		t.Fatalf("unexpected checks %#v", checks)
	}
}

func TestAssetConservationFailsUnaccountedSupply(t *testing.T) {
	p := conservationPolicyFixture()
	d, _ := AssetConservationPolicyDigest(p)
	s := conservationRPCServer(t, "0x65", "0x28", "0x3c")
	defer s.Close()
	r := StaticInvariantPolicyRegistry{AssetConservation: map[string]AssetConservationPolicy{d: p}}
	checks, err := (PolicyBoundInvariantEvaluator{Registry: r}).EvaluatePostState(context.Background(), s.URL, PreparedVerifiedForkRequest{Invariants: []ApprovedInvariantDefinition{{ID: "asset-conservation", Class: InvariantAssetConservation, ParametersSHA256: d}}}, "0x"+strings.Repeat("3", 64))
	if err != nil {
		t.Fatal(err)
	}
	if checks[0].Passed {
		t.Fatal("unaccounted supply passed conservation")
	}
}

func TestAssetConservationRejectsUnknownPolicy(t *testing.T) {
	s := conservationRPCServer(t, "0x64")
	defer s.Close()
	r := StaticInvariantPolicyRegistry{AssetConservation: map[string]AssetConservationPolicy{}}
	_, err := (PolicyBoundInvariantEvaluator{Registry: r}).EvaluatePostState(context.Background(), s.URL, PreparedVerifiedForkRequest{Invariants: []ApprovedInvariantDefinition{{ID: "asset-conservation", Class: InvariantAssetConservation, ParametersSHA256: strings.Repeat("9", 64)}}}, "0x"+strings.Repeat("3", 64))
	if err == nil {
		t.Fatal("unknown asset-conservation policy accepted")
	}
}
