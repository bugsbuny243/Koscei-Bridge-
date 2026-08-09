package web3

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestEvidenceCourtCanonicalHashIgnoresContextSlotAndObjectOrder(t *testing.T) {
	first := json.RawMessage(`{"context":{"slot":100},"value":{"owner":"wallet-a","lamports":42}}`)
	second := json.RawMessage(`{"value":{"lamports":42,"owner":"wallet-a"},"context":{"slot":145}}`)

	firstHash, firstSlot, firstNull, err := evidenceCourtCanonicalHash(first)
	if err != nil {
		t.Fatalf("first canonical hash: %v", err)
	}
	secondHash, secondSlot, secondNull, err := evidenceCourtCanonicalHash(second)
	if err != nil {
		t.Fatalf("second canonical hash: %v", err)
	}
	if firstHash != secondHash {
		t.Fatalf("same state produced different hashes: %s != %s", firstHash, secondHash)
	}
	if firstSlot != 100 || secondSlot != 145 {
		t.Fatalf("unexpected slots: %d %d", firstSlot, secondSlot)
	}
	if firstNull || secondNull {
		t.Fatal("non-null account state marked null")
	}
}

func TestEvaluateEvidenceCourtAcceptsTwoOfThreeAgreement(t *testing.T) {
	samples := []EvidenceCourtSample{
		{Provider: "helius", Host: "api.helius.example", Result: json.RawMessage(`{"context":{"slot":200},"value":{"amount":"10"}}`)},
		{Provider: "alchemy", Host: "solana.alchemy.example", Result: json.RawMessage(`{"context":{"slot":205},"value":{"amount":"10"}}`)},
		{Provider: "quicknode", Host: "solana.quicknode.example", Result: json.RawMessage(`{"context":{"slot":204},"value":{"amount":"11"}}`)},
	}

	result := EvaluateEvidenceCourt("getTokenSupply", samples, 2)
	if result.Status != "verified" {
		t.Fatalf("status=%s want verified", result.Status)
	}
	if result.Available != 3 || result.Matching != 2 {
		t.Fatalf("available=%d matching=%d", result.Available, result.Matching)
	}
	if result.ValueHash == "" {
		t.Fatal("verified quorum missing agreed value hash")
	}
	if result.MinSlot != 200 || result.MaxSlot != 205 || result.SlotSpread != 5 {
		t.Fatalf("unexpected slot window: min=%d max=%d spread=%d", result.MinSlot, result.MaxSlot, result.SlotSpread)
	}
	if len(result.Limitations) != 1 || !strings.Contains(result.Limitations[0], "disagreed") {
		t.Fatalf("expected dissent limitation, got %#v", result.Limitations)
	}
	for _, witness := range result.Witnesses {
		if witness.Host == "invalid-host" || strings.Contains(witness.Host, "/") {
			t.Fatalf("unsafe or invalid witness host: %q", witness.Host)
		}
	}
}

func TestEvaluateEvidenceCourtConflictsWithoutQuorum(t *testing.T) {
	result := EvaluateEvidenceCourt("getAccountInfo", []EvidenceCourtSample{
		{Provider: "helius", Host: "helius.example", Result: json.RawMessage(`{"context":{"slot":10},"value":{"data":"a"}}`)},
		{Provider: "alchemy", Host: "alchemy.example", Result: json.RawMessage(`{"context":{"slot":10},"value":{"data":"b"}}`)},
	}, 2)

	if result.Status != "conflict" {
		t.Fatalf("status=%s want conflict", result.Status)
	}
	if result.ValueHash != "" {
		t.Fatal("conflicting evidence selected an authoritative hash")
	}
}

func TestEvaluateEvidenceCourtFailsClosedWhenWitnessesUnavailable(t *testing.T) {
	result := EvaluateEvidenceCourt("getAccountInfo", []EvidenceCourtSample{
		{Provider: "helius", Host: "helius.example", Result: json.RawMessage(`{"context":{"slot":10},"value":null}`)},
		{Provider: "alchemy", Host: "alchemy.example", Err: errors.New("rpc status 503")},
	}, 2)

	if result.Status != "insufficient" {
		t.Fatalf("status=%s want insufficient", result.Status)
	}
	if result.Available != 1 {
		t.Fatalf("available=%d want 1", result.Available)
	}
	if result.Witnesses[0].Provider == result.Witnesses[1].Provider {
		t.Fatal("witness ordering/deduplication collapsed providers")
	}
}

func TestEvidenceCourtIsDefaultOffAndRejectsUnboundedMethods(t *testing.T) {
	t.Setenv("KOSCHEI_EVIDENCE_COURT_ENABLED", "")
	disabled := (&SolanaRPC{}).EvidenceCourt(context.Background(), "solana-mainnet", "getAccountInfo", []any{"mint"})
	if disabled.Status != "disabled" || disabled.Enabled {
		t.Fatalf("unexpected default state: %#v", disabled)
	}

	t.Setenv("KOSCHEI_EVIDENCE_COURT_ENABLED", "true")
	unsupported := (&SolanaRPC{}).EvidenceCourt(context.Background(), "solana-mainnet", "getSignaturesForAddress", []any{"wallet"})
	if unsupported.Status != "unsupported_method" {
		t.Fatalf("status=%s want unsupported_method", unsupported.Status)
	}
}

func TestEvidenceCourtEndpointsDeduplicateKnownProvidersAndKeepSecretsOutOfMetadata(t *testing.T) {
	t.Setenv("SOLANA_RPC_URL", "https://mainnet.helius-rpc.com/?api-key=top-secret")
	t.Setenv("SOLANA_RPC_FALLBACK_URL", "https://api.mainnet-beta.solana.com")
	t.Setenv("ALCHEMY_SOLANA_RPC_URL", "https://solana-mainnet.g.alchemy.com/v2/another-secret")
	t.Setenv("HELIUS_SOLANA_RPC_URL", "https://secondary.helius.example/v1/duplicate-secret")
	t.Setenv("QUICKNODE_SOLANA_RPC_URL", "https://example.solana-mainnet.quiknode.pro/third-secret")

	client := &SolanaRPC{}
	endpoints := client.evidenceCourtEndpoints("solana-mainnet")
	if len(endpoints) != 4 {
		t.Fatalf("providers=%d want 4: %#v", len(endpoints), endpoints)
	}
	seenHosts := map[string]bool{}
	seenProviders := map[string]bool{}
	for _, endpoint := range endpoints {
		if endpoint.Host == "" || endpoint.Host == "invalid-host" {
			t.Fatalf("invalid endpoint host: %#v", endpoint)
		}
		if seenHosts[endpoint.Host] {
			t.Fatalf("duplicate provider host: %s", endpoint.Host)
		}
		seenHosts[endpoint.Host] = true
		if endpoint.Provider == "helius" || endpoint.Provider == "alchemy" || endpoint.Provider == "quicknode" || endpoint.Provider == "solana_public" {
			if seenProviders[endpoint.Provider] {
				t.Fatalf("known provider counted twice: %s", endpoint.Provider)
			}
			seenProviders[endpoint.Provider] = true
		}
		if strings.Contains(endpoint.Host, "secret") || strings.Contains(endpoint.Provider, "secret") {
			t.Fatalf("secret leaked into safe metadata: %#v", endpoint)
		}
	}
	if !seenProviders["helius"] || !seenProviders["alchemy"] || !seenProviders["quicknode"] || !seenProviders["solana_public"] {
		t.Fatalf("missing expected independent providers: %#v", seenProviders)
	}
}
