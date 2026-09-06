package handlers

import (
	"testing"
	"time"
)

func TestCompatibleSecondHopTransferRequiresAssetAndTimeOrder(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	direct := addressFundingPathSegment{
		Direction:    "inbound",
		Counterparty: "intermediary",
		ObservedAt:   base.Add(10 * time.Minute),
		AssetType:    "SOL",
	}
	transfers := []addressFlowTransfer{
		{Direction: "inbound", Counterparty: "wrong-asset", ObservedAt: base.Add(9 * time.Minute), AssetType: "SPL_TOKEN", TokenMint: "mint-a"},
		{Direction: "inbound", Counterparty: "upstream-old", ObservedAt: base.Add(2 * time.Minute), AssetType: "SOL", Signature: "sig-old"},
		{Direction: "inbound", Counterparty: "upstream-near", ObservedAt: base.Add(8 * time.Minute), AssetType: "SOL", Signature: "sig-near"},
		{Direction: "inbound", Counterparty: "too-late", ObservedAt: base.Add(11 * time.Minute), AssetType: "SOL", Signature: "sig-late"},
	}

	got, direction, ok := compatibleSecondHopTransfer(transfers, direct, "target")
	if !ok {
		t.Fatal("expected compatible upstream transfer")
	}
	if direction != "upstream" {
		t.Fatalf("direction=%q want upstream", direction)
	}
	if got.Counterparty != "upstream-near" || got.Signature != "sig-near" {
		t.Fatalf("selected=%#v want nearest prior SOL transfer", got)
	}
}

func TestCompatibleSecondHopTransferRejectsReturnToTarget(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	direct := addressFundingPathSegment{
		Direction:    "outbound",
		Counterparty: "intermediary",
		ObservedAt:   base,
		AssetType:    "SOL",
	}
	transfers := []addressFlowTransfer{
		{Direction: "outbound", Counterparty: "target", ObservedAt: base.Add(time.Minute), AssetType: "SOL", Signature: "return"},
		{Direction: "outbound", Counterparty: "downstream", ObservedAt: base.Add(2 * time.Minute), AssetType: "SOL", Signature: "forward"},
	}

	got, direction, ok := compatibleSecondHopTransfer(transfers, direct, "target")
	if !ok || direction != "downstream" || got.Counterparty != "downstream" {
		t.Fatalf("selected=%#v direction=%q ok=%v", got, direction, ok)
	}
}

func TestSelectMultiHopExpansionSegmentsPreservesBothSides(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	direct := newAddressFundingPathsReport("target")
	direct.FundingSources = []addressFundingPathSegment{
		{Direction: "inbound", Counterparty: "source-a", ObservedAt: base.Add(2 * time.Minute)},
		{Direction: "inbound", Counterparty: "source-b", ObservedAt: base},
	}
	direct.Downstream = []addressFundingPathSegment{
		{Direction: "outbound", Counterparty: "destination-a", ObservedAt: base.Add(3 * time.Minute)},
	}

	got := selectMultiHopExpansionSegments(direct, 2)
	if len(got) != 2 {
		t.Fatalf("selected=%d want 2", len(got))
	}
	if got[0].Counterparty != "source-a" || got[1].Counterparty != "destination-a" {
		t.Fatalf("selected=%#v", got)
	}
}

func TestMultiHopReportNeverClaimsFungibleTrace(t *testing.T) {
	report := newAddressMultiHopFundingPathsReport("target")
	if report.Policy["fund_trace_claimed"] != false {
		t.Fatalf("fund trace policy changed: %#v", report.Policy)
	}
	if report.Policy["same_actor_claimed"] != false || report.Policy["wrongdoing_claim"] != false {
		t.Fatalf("claim boundary changed: %#v", report.Policy)
	}
}
