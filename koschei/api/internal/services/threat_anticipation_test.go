package services

import (
	"strings"
	"testing"
)

func TestThreatAnticipationClassifiesDominantHolderCapacityWithoutPredictingIntent(t *testing.T) {
	value := 100_000_000.0
	report := BuildThreatAnticipation(ThreatAnticipationInput{
		Target: "mint",
		Market: TokenMarketSnapshot{Available: true, LiquidityUSD: 1_859_470.27},
		Holder: HolderIntelligence{
			Available:                 true,
			TopOwnerPercentage:        58.7504,
			TopOwnerBalance:           587_504,
			TopOwnerReferenceUSDValue: &value,
			Rows: []HolderIntelligenceRow{{
				OwnerWallet: "owner", OwnerResolved: true, RiskBearing: true,
				Balance: 587_504, CirculatingPercentage: 58.7504, ReferenceUSDValue: &value,
			}},
		},
		Arms: []SecurityRadarVerdict{{
			ModuleID: ModuleTokenAuthorityScanner,
			Signed:   true,
			Signals: map[string]any{
				"evidence_status":          "verified",
				"mint_authority_present":   false,
				"freeze_authority_present": false,
			},
		}},
	})

	if !report.ExitCapacity.Available || report.ExitCapacity.Capacity != "critical" {
		t.Fatalf("exit capacity=%#v", report.ExitCapacity)
	}
	if report.ExitCapacity.PositionLiquidityMultiple == nil || *report.ExitCapacity.PositionLiquidityMultiple < 53 {
		t.Fatalf("position/liquidity multiple=%v", report.ExitCapacity.PositionLiquidityMultiple)
	}
	if got := pathwayByID(t, report, "dominant_holder_exit"); got.Status != "open" || got.EvidenceStatus != "observed" {
		t.Fatalf("dominant path=%#v", got)
	}
	if got := pathwayByID(t, report, "mint_inflation"); got.Status != "closed" {
		t.Fatalf("mint path=%#v", got)
	}
	if got := pathwayByID(t, report, "freeze_abuse"); got.Status != "closed" {
		t.Fatalf("freeze path=%#v", got)
	}
	if got := pathwayByID(t, report, "liquidity_removal"); got.Status != "unknown" {
		t.Fatalf("liquidity path=%#v", got)
	}
	if report.RugAssessment.ProbabilityMode != "not_scored" || report.EvidencePolicy["predicts_intent"] {
		t.Fatalf("policy=%#v rug=%#v", report.EvidencePolicy, report.RugAssessment)
	}
	if !strings.Contains(strings.ToLower(report.ExitCapacity.Interpretation), "not intent") {
		t.Fatalf("interpretation=%q", report.ExitCapacity.Interpretation)
	}
}

func TestThreatAnticipationDetectsObservedCommonExit(t *testing.T) {
	report := BuildThreatAnticipation(ThreatAnticipationInput{
		Target: "mint",
		Cluster: HolderClusterAnalysis{
			Available: true,
			Flow:      HolderClusterFlowAnalysis{Available: true, CommonExitGroupCount: 1},
		},
	})
	path := pathwayByID(t, report, "coordinated_holder_exit")
	if path.Status != "observed" || path.Capacity != "high" {
		t.Fatalf("path=%#v", path)
	}
}

func TestThreatAnticipationUsesVerifiedUnlockedLPStatus(t *testing.T) {
	report := BuildThreatAnticipation(ThreatAnticipationInput{
		Target: "mint",
		Arms: []SecurityRadarVerdict{{
			ModuleID: ModuleLiquidityMovement,
			Signed:   true,
			Signals: map[string]any{
				"evidence_status": "verified",
				"lp_lock_status":  "unlocked",
			},
		}},
	})
	path := pathwayByID(t, report, "liquidity_removal")
	if path.Status != "open" || path.Capacity != "high" || path.EvidenceStatus != "verified" {
		t.Fatalf("path=%#v", path)
	}
}

func TestThreatAnticipationDoesNotTreatExcludedProtocolInventoryAsOwnerCapacity(t *testing.T) {
	value := 5_000_000.0
	report := BuildThreatAnticipation(ThreatAnticipationInput{
		Target: "mint",
		Market: TokenMarketSnapshot{Available: true, LiquidityUSD: 1_000_000},
		Holder: HolderIntelligence{
			Available: true,
			Rows: []HolderIntelligenceRow{{
				OwnerWallet: "pool", OwnerResolved: true, RiskBearing: false,
				ExcludedFromHolderRisk: true, RawPercentage: 70, ReferenceUSDValue: &value,
			}},
		},
	})
	if report.ExitCapacity.Available {
		t.Fatalf("protocol inventory became owner capacity: %#v", report.ExitCapacity)
	}
	if got := pathwayByID(t, report, "dominant_holder_exit"); got.Status != "unknown" {
		t.Fatalf("dominant path=%#v", got)
	}
}

func TestThreatAnticipationMissingDataNeverBecomesSafe(t *testing.T) {
	report := BuildThreatAnticipation(ThreatAnticipationInput{Target: "mint"})
	if report.Status != "insufficient_evidence" {
		t.Fatalf("status=%q", report.Status)
	}
	if len(report.RugAssessment.UnknownPaths) == 0 {
		t.Fatalf("rug assessment=%#v", report.RugAssessment)
	}
	if strings.Contains(strings.ToLower(report.PrimaryExposure), "safe") {
		t.Fatalf("unsafe safe claim=%q", report.PrimaryExposure)
	}
}

func pathwayByID(t *testing.T, report ThreatAnticipationReport, id string) ThreatPathway {
	t.Helper()
	for _, path := range report.Pathways {
		if path.ID == id {
			return path
		}
	}
	t.Fatalf("path %s not found", id)
	return ThreatPathway{}
}
