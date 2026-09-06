package handlers

import (
	"testing"
	"time"
)

func TestBuildAddressInteractionsUsesVerifiedAttributionOnly(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	flow := newAddressFlowReport("target-wallet", "solana-mainnet")
	flow.FlowComplete = true
	flow.Counterparties = []addressFlowCounterparty{
		{Address: "known-cex", InboundTransfers: 2, SOLIn: 4},
		{Address: "unknown-wallet", OutboundTransfers: 1, SOLOut: 1},
	}
	flow.Transfers = []addressFlowTransfer{
		{Direction: "inbound", Counterparty: "known-cex", Signature: "sig-1", ObservedAt: now, VerificationStatus: "verified", Source: "solana_jsonparsed_transaction"},
		{Direction: "outbound", Counterparty: "unknown-wallet", Signature: "sig-2", ObservedAt: now.Add(time.Minute), VerificationStatus: "verified", Source: "solana_jsonparsed_transaction"},
	}
	attribution := newAddressAttributionReport("target-wallet")
	attribution.Entities = []addressAttributionEntity{
		{Address: "known-cex", Entity: "Binance", Category: "Centralized Exchange", Source: "helius_identity", Verification: "provider_verified"},
	}

	report := buildAddressInteractions("target-wallet", flow, attribution)
	if report.ClassifiedCount != 1 || report.UnknownCount != 1 {
		t.Fatalf("classified=%d unknown=%d", report.ClassifiedCount, report.UnknownCount)
	}
	if len(report.Interactions) != 2 {
		t.Fatalf("interactions=%d want 2", len(report.Interactions))
	}
	var known, unknown *addressInteraction
	for i := range report.Interactions {
		switch report.Interactions[i].Address {
		case "known-cex":
			known = &report.Interactions[i]
		case "unknown-wallet":
			unknown = &report.Interactions[i]
		}
	}
	if known == nil || known.InteractionKind != "CEX" || known.Verification != "provider_verified_taxonomy_and_direct_onchain_flow" {
		t.Fatalf("known interaction = %#v", known)
	}
	if len(known.EvidenceSignatures) != 1 || known.EvidenceSignatures[0] != "sig-1" {
		t.Fatalf("known evidence signatures = %#v", known.EvidenceSignatures)
	}
	if unknown == nil || unknown.InteractionKind != "UNKNOWN" {
		t.Fatalf("unknown interaction = %#v", unknown)
	}
	if unknown.Entity != "" || unknown.Name != "" || unknown.RiskFlag != "" {
		t.Fatalf("unverified counterparty gained invented attribution: %#v", unknown)
	}
	if report.Policy["same_actor_claimed"] != false || report.Policy["wrongdoing_claim"] != false {
		t.Fatalf("claim boundary changed: %#v", report.Policy)
	}
}
