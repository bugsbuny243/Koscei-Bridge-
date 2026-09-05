package handlers

import (
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestBuildAddressBehaviorTimelineSortsTransferAndMintEvidence(t *testing.T) {
	transferTime := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	mintTime := transferTime.Add(-24 * time.Hour)
	flow := addressFlowReport{
		FlowComplete: true,
		Transfers: []addressFlowTransfer{{
			Direction: "outbound", AssetType: "SOL", Counterparty: "WalletB", Signature: "sig-transfer",
			Slot: 20, ObservedAt: transferTime, AmountNative: 2.5,
			VerificationStatus: "verified", Source: "solana_jsonparsed_instruction",
		}},
	}
	created := actorCreatedMintIntegrationRun{
		Status:              "verified_candidates_available",
		CandidatesRequested: 1,
		CandidatesVerified:  1,
		VerifiedCandidates: []services.ActorCreatedMintCandidate{{
			Mint: "MintA", Signature: "sig-mint", Slot: 10, ObservedAt: mintTime,
			Program: "TokenProgram", VerificationStatus: "verified", Source: "solana_jsonparsed_instruction",
		}},
	}

	report := buildAddressBehaviorTimeline("WalletA", flow, created)
	if report.EventCount != 2 || report.Status != "timestamped_behavior_available" {
		t.Fatalf("report=%#v", report)
	}
	if report.Events[0].EventType != "mint_created" || report.Events[1].EventType != "transfer_out" {
		t.Fatalf("events=%#v", report.Events)
	}
	if report.Events[1].Counterparty != "WalletB" || report.Events[1].AmountNative != 2.5 {
		t.Fatalf("transfer event=%#v", report.Events[1])
	}
	if !report.Coverage.DirectFlowComplete || report.Coverage.CreatedMintVerified != 1 {
		t.Fatalf("coverage=%#v", report.Coverage)
	}
}

func TestBuildAddressBehaviorTimelineUsesBlockTimeFallback(t *testing.T) {
	blockTime := int64(1788256800)
	created := actorCreatedMintIntegrationRun{
		Status:              "verified_candidates_available",
		CandidatesRequested: 1,
		CandidatesVerified:  1,
		VerifiedCandidates: []services.ActorCreatedMintCandidate{{
			Mint: "MintA", Signature: "sig-mint", BlockTime: blockTime,
			VerificationStatus: "verified", Source: "solana_jsonparsed_instruction",
		}},
	}
	report := buildAddressBehaviorTimeline("WalletA", addressFlowReport{FlowComplete: true}, created)
	if report.EventCount != 1 {
		t.Fatalf("report=%#v", report)
	}
	want := time.Unix(blockTime, 0).UTC()
	if !report.Events[0].ObservedAt.Equal(want) {
		t.Fatalf("observed_at=%s want=%s", report.Events[0].ObservedAt, want)
	}
}

func TestBuildAddressBehaviorTimelineOmitsUntimedEvidenceAndReportsCoverage(t *testing.T) {
	flow := addressFlowReport{
		FlowComplete: false,
		Transfers: []addressFlowTransfer{{
			Direction: "inbound", AssetType: "SOL", Counterparty: "WalletB", Signature: "sig-no-time",
		}},
	}
	created := actorCreatedMintIntegrationRun{
		Status:              "partial_verification",
		CandidatesRequested: 2,
		CandidatesVerified:  1,
		VerifiedCandidates: []services.ActorCreatedMintCandidate{{
			Mint: "MintNoTime", Signature: "sig-mint-no-time", VerificationStatus: "verified",
		}},
	}
	report := buildAddressBehaviorTimeline("WalletA", flow, created)
	if report.EventCount != 0 || report.EventsSkippedNoTime != 2 {
		t.Fatalf("report=%#v", report)
	}
	if len(report.Limitations) < 3 {
		t.Fatalf("limitations=%#v", report.Limitations)
	}
	if report.Coverage.DirectFlowComplete {
		t.Fatalf("coverage=%#v", report.Coverage)
	}
}
