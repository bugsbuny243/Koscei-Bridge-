package services

import (
	"strings"
	"testing"
	"time"
)

func c005Holder(share float64) HolderIntelligence {
	return HolderIntelligence{
		Available:               true,
		OwnerAggregationApplied: true,
		CirculatingSupply:       1_000_000,
		TopOwnerPercentage:      share,
		Rows: []HolderIntelligenceRow{
			{
				Rank:                   1,
				OwnerWallet:            "Owner111111111111111111111111111111111",
				OwnerResolved:          true,
				RiskBearing:            true,
				ExcludedFromHolderRisk: false,
				Role:                   "externally_owned_wallet",
				RoleConfidence:         "high",
			},
		},
	}
}

func TestC005OwnerResolvedFThreshold(t *testing.T) {
	now := time.Date(2026, 7, 17, 6, 0, 0, 0, time.UTC)
	behavior := UnifiedRadarBehaviorReport{Mint: "MintF", Signals: []UnifiedRadarSignal{}, Evidence: []ActorDefenseEvidenceRecord{}, GeneratedAt: now}
	behavior = ApplyOwnerConcentrationRuleV110(behavior, c005Holder(70), now)

	if behavior.RulesetVersion != UnifiedRadarRulesetVersionV110 {
		t.Fatalf("ruleset=%q", behavior.RulesetVersion)
	}
	if len(behavior.Signals) != 1 {
		t.Fatalf("signals=%d", len(behavior.Signals))
	}
	signal := behavior.Signals[0]
	if !signal.Triggered || signal.EvidenceStatus != "verified" || signal.GradeEffect != "hard_cap_F" {
		t.Fatalf("signal=%#v", signal)
	}
	if len(signal.EvidenceKeys) != 1 || signal.EvidenceKeys[0] != "owner:Owner111111111111111111111111111111111" {
		t.Fatalf("evidence_keys=%v", signal.EvidenceKeys)
	}

	verdict := EvaluateUnifiedRadarVerdictV110("MintF", ActorDefenseRuleVerdict{}, behavior)
	if verdict.Grade != "F" || verdict.Verdict != "hard_trigger" || !verdict.Signed || verdict.Signature == "" {
		t.Fatalf("verdict=%#v", verdict)
	}
}

func TestC005OwnerResolvedDThreshold(t *testing.T) {
	now := time.Date(2026, 7, 17, 6, 0, 0, 0, time.UTC)
	behavior := UnifiedRadarBehaviorReport{Mint: "MintD", Signals: []UnifiedRadarSignal{}, Evidence: []ActorDefenseEvidenceRecord{}, GeneratedAt: now}
	behavior = ApplyOwnerConcentrationRuleV110(behavior, c005Holder(50), now)
	verdict := EvaluateUnifiedRadarVerdictV110("MintD", ActorDefenseRuleVerdict{}, behavior)

	if behavior.Signals[0].GradeEffect != "hard_cap_D" || verdict.Grade != "D" || !verdict.Signed {
		t.Fatalf("behavior=%#v verdict=%#v", behavior, verdict)
	}
}

func TestC005RawTokenAccountConcentrationCannotTrigger(t *testing.T) {
	now := time.Date(2026, 7, 17, 6, 0, 0, 0, time.UTC)
	holder := c005Holder(95)
	holder.OwnerAggregationApplied = false
	holder.Rows = []HolderIntelligenceRow{
		{Rank: 1, RawPercentage: 95, OwnerResolved: false, RiskBearing: true},
	}
	behavior := UnifiedRadarBehaviorReport{Mint: "RawAccountMint", Signals: []UnifiedRadarSignal{}, Evidence: []ActorDefenseEvidenceRecord{}, GeneratedAt: now}
	behavior = ApplyOwnerConcentrationRuleV110(behavior, holder, now)
	signal := behavior.Signals[0]

	if signal.Triggered || signal.EvidenceStatus != "unverified" || signal.GradeEffect != "none" {
		t.Fatalf("raw account concentration triggered C005: %#v", signal)
	}
	verdict := EvaluateUnifiedRadarVerdictV110("RawAccountMint", ActorDefenseRuleVerdict{}, behavior)
	if verdict.Grade != "-" || verdict.Signed {
		t.Fatalf("raw account verdict=%#v", verdict)
	}
}

func TestC005ExcludedInfrastructureOwnerCannotTrigger(t *testing.T) {
	now := time.Date(2026, 7, 17, 6, 0, 0, 0, time.UTC)
	holder := c005Holder(88)
	holder.Rows[0].ExcludedFromHolderRisk = true
	behavior := UnifiedRadarBehaviorReport{Mint: "InfraMint", Signals: []UnifiedRadarSignal{}, Evidence: []ActorDefenseEvidenceRecord{}, GeneratedAt: now}
	behavior = ApplyOwnerConcentrationRuleV110(behavior, holder, now)

	if behavior.Signals[0].Triggered || behavior.Signals[0].EvidenceStatus != "unverified" {
		t.Fatalf("infrastructure owner triggered C005: %#v", behavior.Signals[0])
	}
}

func TestC005UnidentifiedDominantOwnerCannotHardCap(t *testing.T) {
	now := time.Date(2026, 9, 6, 6, 0, 0, 0, time.UTC)
	for _, role := range []string{
		"program_controlled_unresolved",
		"owner_unresolved",
		"wallet_account_unavailable",
		"",
	} {
		holder := c005Holder(95.7596)
		holder.Rows[0].Role = role
		holder.Rows[0].RoleConfidence = "medium"
		behavior := UnifiedRadarBehaviorReport{Mint: "UnresolvedMint", Signals: []UnifiedRadarSignal{}, Evidence: []ActorDefenseEvidenceRecord{}, GeneratedAt: now}
		behavior = ApplyOwnerConcentrationRuleV110(behavior, holder, now)

		signal := behavior.Signals[0]
		if signal.GradeEffect != "none" {
			t.Fatalf("role %q produced grade effect %q; an unidentified owner must not cap the grade", role, signal.GradeEffect)
		}
		if signal.EvidenceStatus != "inferred" {
			t.Fatalf("role %q produced evidence status %q, want inferred so the rule stays watch-only", role, signal.EvidenceStatus)
		}

		verdict := EvaluateUnifiedRadarVerdictV110("UnresolvedMint", ActorDefenseRuleVerdict{Grade: "-"}, behavior)
		if verdict.Grade == "F" || verdict.Grade == "D" {
			t.Fatalf("role %q still graded %s", role, verdict.Grade)
		}
		if len(verdict.WatchFlags) == 0 {
			t.Fatalf("role %q dropped the finding entirely; it must remain visible as a watch flag", role)
		}
	}
}

func TestC005IdentifiedWalletStillHardCapsAtF(t *testing.T) {
	now := time.Date(2026, 9, 6, 6, 0, 0, 0, time.UTC)
	holder := c005Holder(95.7596)
	holder.Rows[0].Role = "externally_owned_wallet"
	holder.Rows[0].RoleConfidence = "high"
	behavior := UnifiedRadarBehaviorReport{Mint: "WhaleMint", Signals: []UnifiedRadarSignal{}, Evidence: []ActorDefenseEvidenceRecord{}, GeneratedAt: now}
	behavior = ApplyOwnerConcentrationRuleV110(behavior, holder, now)

	if behavior.Signals[0].GradeEffect != "hard_cap_F" {
		t.Fatalf("identified whale did not cap at F: %#v", behavior.Signals[0])
	}
	if verdict := EvaluateUnifiedRadarVerdictV110("WhaleMint", ActorDefenseRuleVerdict{Grade: "-"}, behavior); verdict.Grade != "F" {
		t.Fatalf("verdict grade=%q, want F", verdict.Grade)
	}
}

func TestC005UnidentifiedSignalNamesTheRole(t *testing.T) {
	now := time.Date(2026, 9, 6, 6, 0, 0, 0, time.UTC)
	holder := c005Holder(95.7596)
	holder.Rows[0].Role = "program_controlled_unresolved"
	behavior := UnifiedRadarBehaviorReport{Mint: "NamedMint", Signals: []UnifiedRadarSignal{}, Evidence: []ActorDefenseEvidenceRecord{}, GeneratedAt: now}
	behavior = ApplyOwnerConcentrationRuleV110(behavior, holder, now)

	signal := behavior.Signals[0]
	if !strings.Contains(signal.Summary, "program_controlled_unresolved") {
		t.Fatalf("summary does not name the unresolved role: %q", signal.Summary)
	}
	if got := signal.Metrics["top_owner_role_identified"]; got != false {
		t.Fatalf("top_owner_role_identified=%v, want false", got)
	}
	if got := signal.Metrics["top_owner_role"]; got != "program_controlled_unresolved" {
		t.Fatalf("top_owner_role=%v", got)
	}
}
