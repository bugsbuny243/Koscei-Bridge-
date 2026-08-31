package services

import "testing"

func TestCreatorLinkEvidenceStaysObservedWithoutCanonicalCreateAnchor(t *testing.T) {
	req := SecurityRadarRequest{Target: "MintCreatorObserved11111111111111111111111111", Network: "solana-mainnet", Mode: "manual_test"}
	launch := LaunchForensicsAnalysis{
		DataSource:       "live_ledger",
		LaunchSlot:       123,
		LaunchTimeSource: "source_launch_event",
	}
	arm := creatorLinkEvidenceArm(req, "CreatorObserved111111111111111111111111111", launch, "2026-08-31T00:00:00Z")

	if !arm.Signed {
		t.Fatal("observed creator evidence should remain a signed evidence arm")
	}
	if got, _ := arm.Signals["real_onchain_evidence"].(bool); got {
		t.Fatal("source attribution was incorrectly upgraded to real_onchain_evidence")
	}
	if got, _ := arm.Signals["real_offchain_evidence"].(bool); !got {
		t.Fatal("observed source attribution should be represented as off-chain/source evidence")
	}
	if got, _ := arm.Signals["verified_evidence"].(bool); got {
		t.Fatal("observed source attribution was incorrectly marked verified")
	}
	if got := arm.Signals["evidence_status"]; got != "observed" {
		t.Fatalf("evidence_status=%v", got)
	}
	if got, _ := arm.Signals["creator_relation_verified"].(bool); got {
		t.Fatal("creator relation should remain observed-only")
	}
}

func TestCreatorLinkEvidenceUpgradesWithCanonicalCreateAnchor(t *testing.T) {
	req := SecurityRadarRequest{Target: "MintCreatorVerified11111111111111111111111111", Network: "solana-mainnet", Mode: "manual_test"}
	launch := LaunchForensicsAnalysis{
		DataSource:       "ata_history",
		LaunchSlot:       456,
		LaunchTimeSource: "verified_canonical_create_transaction",
	}
	arm := creatorLinkEvidenceArm(req, "CreatorVerified11111111111111111111111111", launch, "2026-08-31T00:00:00Z")

	if !arm.Signed {
		t.Fatal("verified creator evidence should be signed")
	}
	if got, _ := arm.Signals["real_onchain_evidence"].(bool); !got {
		t.Fatal("canonical creator evidence should be real_onchain_evidence")
	}
	if got, _ := arm.Signals["real_offchain_evidence"].(bool); got {
		t.Fatal("canonical creator evidence should not be downgraded to source-only evidence")
	}
	if got, _ := arm.Signals["verified_evidence"].(bool); !got {
		t.Fatal("canonical creator evidence should be verified")
	}
	if got := arm.Signals["evidence_status"]; got != "verified" {
		t.Fatalf("evidence_status=%v", got)
	}
	if got, _ := arm.Signals["creator_relation_verified"].(bool); !got {
		t.Fatal("canonical creator relation should be marked verified")
	}
	if got := arm.Signals["launch_slot"]; got != int64(456) {
		t.Fatalf("launch_slot=%v", got)
	}
}

func TestCreatorLinkCanonicalLabelWithoutSlotCannotVerify(t *testing.T) {
	launch := LaunchForensicsAnalysis{LaunchTimeSource: "verified_canonical_create_transaction"}
	if creatorRelationCanonicalVerified(launch) {
		t.Fatal("canonical label without positive slot must fail closed")
	}
}
