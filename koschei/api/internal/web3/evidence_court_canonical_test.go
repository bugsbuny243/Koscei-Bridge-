package web3

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestEvaluateEvidenceCourtWithCanonicalizerUsesDomainHash(t *testing.T) {
	canonicalize := func(raw json.RawMessage) (string, uint64, bool, error) {
		var value struct {
			Root string `json:"root"`
			Slot uint64 `json:"slot"`
		}
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", 0, false, err
		}
		return value.Root, value.Slot, false, nil
	}
	result := EvaluateEvidenceCourtWithCanonicalizer("getMultipleAccounts", []EvidenceCourtSample{
		{Provider: "helius", Host: "helius.example", Result: json.RawMessage(`{"root":"state-root-a","slot":220}`)},
		{Provider: "alchemy", Host: "alchemy.example", Result: json.RawMessage(`{"root":"state-root-a","slot":225}`)},
		{Provider: "quicknode", Host: "quicknode.example", Result: json.RawMessage(`{"root":"state-root-b","slot":224}`)},
	}, 2, canonicalize)
	if result.Status != "verified" || result.ValueHash != "state-root-a" {
		t.Fatalf("result=%#v", result)
	}
	if result.Matching != 2 || result.Available != 3 {
		t.Fatalf("matching=%d available=%d", result.Matching, result.Available)
	}
}

func TestEvaluateEvidenceCourtWithCanonicalizerFailsClosedOnCanonicalizationError(t *testing.T) {
	canonicalize := func(raw json.RawMessage) (string, uint64, bool, error) {
		if string(raw) == `"bad"` {
			return "", 0, false, errors.New("bad state")
		}
		return "same-root", 300, false, nil
	}
	result := EvaluateEvidenceCourtWithCanonicalizer("getMultipleAccounts", []EvidenceCourtSample{
		{Provider: "helius", Host: "helius.example", Result: json.RawMessage(`"ok"`)},
		{Provider: "alchemy", Host: "alchemy.example", Result: json.RawMessage(`"bad"`)},
	}, 2, canonicalize)
	if result.Status != "insufficient" || result.Available != 1 {
		t.Fatalf("result=%#v", result)
	}
	if len(result.Witnesses) != 2 || result.Witnesses[0].Status == "" || result.Witnesses[1].Status == "" {
		t.Fatalf("witnesses=%#v", result.Witnesses)
	}
}

func TestEvaluateEvidenceCourtWithCanonicalizerRejectsNilCanonicalizer(t *testing.T) {
	result := EvaluateEvidenceCourtWithCanonicalizer("getMultipleAccounts", nil, 2, nil)
	if result.Status != "insufficient" || len(result.Limitations) == 0 {
		t.Fatalf("result=%#v", result)
	}
}

func TestEvidenceCourtEndpointsExcludingRemovesEntirePrimaryProviderIdentity(t *testing.T) {
	endpoints := []evidenceCourtEndpoint{
		{Provider: "helius", Host: "mainnet.helius-rpc.com", URL: "https://mainnet.helius-rpc.com/?api-key=one"},
		{Provider: "helius", Host: "rpc.helius.xyz", URL: "https://rpc.helius.xyz/?api-key=two"},
		{Provider: "alchemy", Host: "solana-mainnet.g.alchemy.com", URL: "https://solana-mainnet.g.alchemy.com/v2/test"},
		{Provider: "quicknode", Host: "example.quiknode.pro", URL: "https://example.quiknode.pro/test"},
	}
	got := evidenceCourtEndpointsExcluding(endpoints, "https://mainnet.helius-rpc.com/?api-key=primary")
	if len(got) != 2 {
		t.Fatalf("endpoints=%#v", got)
	}
	for _, endpoint := range got {
		if endpoint.Provider == "helius" {
			t.Fatalf("primary provider identity remained in quorum: %#v", got)
		}
	}
}

func TestEvidenceCourtEndpointsExcludingCustomHostUsesExactHostIdentity(t *testing.T) {
	endpoints := []evidenceCourtEndpoint{
		{Provider: "rpc-a.internal.example", Host: "rpc-a.internal.example", URL: "https://rpc-a.internal.example"},
		{Provider: "rpc-b.internal.example", Host: "rpc-b.internal.example", URL: "https://rpc-b.internal.example"},
	}
	got := evidenceCourtEndpointsExcluding(endpoints, "https://rpc-a.internal.example/path")
	if len(got) != 1 || got[0].Host != "rpc-b.internal.example" {
		t.Fatalf("endpoints=%#v", got)
	}
}
