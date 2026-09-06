package handlers

import (
	"testing"
	"time"
)

func TestBuildAddressFundingPathsPairsMostRecentCompatibleSource(t *testing.T) {
	base := time.Date(2026, 9, 6, 1, 0, 0, 0, time.UTC)
	flow := newAddressFlowReport("target", "solana-mainnet")
	flow.FlowComplete = true
	flow.Transfers = []addressFlowTransfer{
		{Direction: "inbound", AssetType: "SOL", Counterparty: "source-old", Signature: "sig-in-old", Slot: 10, ObservedAt: base, AmountNative: 3, VerificationStatus: "verified", Source: "rpc"},
		{Direction: "inbound", AssetType: "SOL", Counterparty: "source-new", Signature: "sig-in-new", Slot: 20, ObservedAt: base.Add(5 * time.Minute), AmountNative: 2, VerificationStatus: "verified", Source: "rpc"},
		{Direction: "outbound", AssetType: "SOL", Counterparty: "destination", Signature: "sig-out", Slot: 30, ObservedAt: base.Add(9 * time.Minute), AmountNative: 1, VerificationStatus: "verified", Source: "rpc"},
	}

	report := buildAddressFundingPaths("target", flow, newAddressAttributionReport("target"))
	if report.Status != "observed_source_to_downstream_sequences_available" {
		t.Fatalf("status=%q", report.Status)
	}
	if report.PathCandidateCount != 1 {
		t.Fatalf("path_candidate_count=%d want 1", report.PathCandidateCount)
	}
	candidate := report.PathCandidates[0]
	if candidate.SourceSegment.Counterparty != "source-new" {
		t.Fatalf("source=%q want source-new", candidate.SourceSegment.Counterparty)
	}
	if candidate.DownstreamSegment.Counterparty != "destination" {
		t.Fatalf("downstream=%q want destination", candidate.DownstreamSegment.Counterparty)
	}
	if candidate.ElapsedSeconds != 240 {
		t.Fatalf("elapsed_seconds=%d want 240", candidate.ElapsedSeconds)
	}
	if !candidate.AssetContinuity {
		t.Fatal("compatible SOL sequence must preserve asset continuity")
	}
	if candidate.FundTraceClaimed {
		t.Fatal("temporal sequence must never claim fungible fund tracing")
	}
}

func TestBuildAddressFundingPathsRequiresSameTokenMint(t *testing.T) {
	base := time.Date(2026, 9, 6, 1, 0, 0, 0, time.UTC)
	flow := newAddressFlowReport("target", "solana-mainnet")
	flow.Transfers = []addressFlowTransfer{
		{Direction: "inbound", AssetType: "SPL_TOKEN", TokenMint: "MintA", Counterparty: "source", Signature: "sig-in", ObservedAt: base, TokenAmount: 100, VerificationStatus: "verified", Source: "rpc"},
		{Direction: "outbound", AssetType: "SPL_TOKEN", TokenMint: "MintB", Counterparty: "destination", Signature: "sig-out", ObservedAt: base.Add(time.Minute), TokenAmount: 50, VerificationStatus: "verified", Source: "rpc"},
	}

	report := buildAddressFundingPaths("target", flow, newAddressAttributionReport("target"))
	if report.PathCandidateCount != 0 {
		t.Fatalf("path_candidate_count=%d want 0", report.PathCandidateCount)
	}
	if report.Status != "direct_sources_and_downstream_observed_without_compatible_sequence" {
		t.Fatalf("status=%q", report.Status)
	}
}

func TestBuildAddressFundingPathsAttachesVerifiedEndpointAttribution(t *testing.T) {
	base := time.Date(2026, 9, 6, 1, 0, 0, 0, time.UTC)
	flow := newAddressFlowReport("target", "solana-mainnet")
	flow.Transfers = []addressFlowTransfer{
		{Direction: "inbound", AssetType: "SOL", Counterparty: "known-source", Signature: "sig-in", ObservedAt: base, VerificationStatus: "verified", Source: "rpc"},
		{Direction: "outbound", AssetType: "SOL", Counterparty: "unknown-destination", Signature: "sig-out", ObservedAt: base.Add(time.Minute), VerificationStatus: "verified", Source: "rpc"},
	}
	attribution := newAddressAttributionReport("target")
	attribution.Entities = []addressAttributionEntity{{
		Address: "known-source", Name: "Known Source", Entity: "exchange", Category: "cex", Source: "helius_wallet_identity", Verification: "provider_verified",
	}}

	report := buildAddressFundingPaths("target", flow, attribution)
	if len(report.FundingSources) != 1 || report.FundingSources[0].Endpoint == nil {
		t.Fatal("verified source attribution missing")
	}
	endpoint := report.FundingSources[0].Endpoint
	if endpoint.Entity != "exchange" || endpoint.Verification != "provider_verified" {
		t.Fatalf("unexpected endpoint attribution: %#v", endpoint)
	}
	if report.Downstream[0].Endpoint != nil {
		t.Fatal("unknown destination must remain unattributed")
	}
}

func TestBuildAddressFundingPathsPropagatesBoundedCoverage(t *testing.T) {
	flow := newAddressFlowReport("target", "solana-mainnet")
	flow.FlowComplete = false
	report := buildAddressFundingPaths("target", flow, newAddressAttributionReport("target"))
	if report.FlowComplete {
		t.Fatal("bounded source flow must remain incomplete")
	}
	found := false
	for _, limitation := range report.Limitations {
		if limitation == "Direct fund-flow coverage is bounded; unseen transactions may contain earlier funding sources or additional downstream destinations." {
			found = true
		}
	}
	if !found {
		t.Fatalf("bounded coverage limitation missing: %#v", report.Limitations)
	}
	if claimed, _ := report.Policy["fund_trace_claimed"].(bool); claimed {
		t.Fatal("policy must never claim fungible fund tracing")
	}
}
