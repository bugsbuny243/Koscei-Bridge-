package services

import "testing"

func TestUnifiedRadarVerdictFingerprintIsStable(t *testing.T) {
	verdict := UnifiedRadarVerdict{
		Grade: "B", Verdict: "compounding_rule", RulesetVersion: UnifiedRadarRulesetVersion,
		ActorRuleset: ActorDefenseRulesetVersion,
		TriggeredRules: []ActorDefenseRuleHit{{
			RuleID: UnifiedRuleVolumeLiquidityGap, EvidenceStatus: "observed",
			Tier: "compounding", EvidenceKeys: []string{"market:one"},
		}},
	}
	behavior := UnifiedRadarBehaviorReport{Signals: []UnifiedRadarSignal{{
		RuleID: UnifiedRuleVolumeLiquidityGap, EvidenceStatus: "observed", Triggered: true,
		Metrics: map[string]any{"ratio": 8.0},
	}}}
	first, err := UnifiedRadarVerdictFingerprint("solana-mainnet", "token", "MintOne", verdict, behavior)
	if err != nil {
		t.Fatal(err)
	}
	second, err := UnifiedRadarVerdictFingerprint("solana-mainnet", "token", "MintOne", verdict, behavior)
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first != second {
		t.Fatalf("fingerprints %q %q", first, second)
	}
}

func TestUnifiedRadarVerdictFingerprintChangesWithRules(t *testing.T) {
	base := UnifiedRadarVerdict{
		Grade: "B", Verdict: "compounding_rule", RulesetVersion: UnifiedRadarRulesetVersion,
		ActorRuleset:   ActorDefenseRulesetVersion,
		TriggeredRules: []ActorDefenseRuleHit{{RuleID: UnifiedRuleVolumeLiquidityGap, EvidenceStatus: "observed"}},
	}
	changed := base
	changed.TriggeredRules = []ActorDefenseRuleHit{{RuleID: UnifiedRuleDominantHolderFirstExit, EvidenceStatus: "verified"}}
	first, _ := UnifiedRadarVerdictFingerprint("solana-mainnet", "token", "MintOne", base, UnifiedRadarBehaviorReport{})
	second, _ := UnifiedRadarVerdictFingerprint("solana-mainnet", "token", "MintOne", changed, UnifiedRadarBehaviorReport{})
	if first == second {
		t.Fatalf("rule change did not change fingerprint: %q", first)
	}
}

func TestNormalizeUnifiedGradeDoesNotInventA(t *testing.T) {
	if got := normalizeUnifiedGrade(""); got != "-" {
		t.Fatalf("empty grade=%q", got)
	}
	if got := normalizeUnifiedGrade("unknown"); got != "-" {
		t.Fatalf("unknown grade=%q", got)
	}
}

func TestNormalizeUnifiedGradePreservesF(t *testing.T) {
	if got := normalizeUnifiedGrade("f"); got != "F" {
		t.Fatalf("F grade normalized to %q", got)
	}
}
