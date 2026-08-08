package services

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUnifiedRuntimeContractAcceptsNoGradeVerdict(t *testing.T) {
	rawVerdict := EvaluateUnifiedRadarVerdict("MintOne", ActorDefenseRuleVerdict{}, UnifiedRadarBehaviorReport{})
	if rawVerdict.Grade != "-" {
		t.Fatalf("expected withheld grade, got %q", rawVerdict.Grade)
	}

	encoded, err := json.Marshal(rawVerdict)
	if err != nil {
		t.Fatalf("marshal runtime contract: %v", err)
	}
	var contract map[string]any
	if err := json.Unmarshal(encoded, &contract); err != nil {
		t.Fatalf("decode runtime contract: %v", err)
	}
	if contract["grade"] != "-" {
		t.Fatalf("contract grade=%v", contract["grade"])
	}
	if contract["signed"] != true {
		t.Fatalf("no-grade contract must be signed deterministic state: %v", contract["signed"])
	}
	if contract["rule_version"] != UnifiedRadarRulesetVersion {
		t.Fatalf("rule_version=%v", contract["rule_version"])
	}
	if _, exists := contract["risk_index"]; exists {
		t.Fatal("numeric risk_index leaked into signed contract")
	}
	if _, exists := contract["risk_level"]; exists {
		t.Fatal("risk_level leaked into numberless signed contract")
	}
	evidence, ok := contract["evidence"].([]any)
	if !ok || len(evidence) == 0 {
		t.Fatalf("contract evidence=%#v", contract["evidence"])
	}
	if rules, ok := contract["triggered_rules"].([]any); !ok || len(rules) != 0 {
		t.Fatalf("no-grade triggered_rules=%#v", contract["triggered_rules"])
	}
	decision, ok := contract["decision_path"].([]any)
	if !ok || len(decision) == 0 {
		t.Fatalf("decision_path=%#v", contract["decision_path"])
	}
	if signature, _ := contract["signature"].(string); !strings.HasPrefix(signature, "koschei-unified-contract:") {
		t.Fatalf("fallback contract signature=%q", signature)
	}
}

func TestFinalizeUnifiedRuntimeContractBindsTarget(t *testing.T) {
	verdict := EvaluateUnifiedRadarVerdict("MintOne", ActorDefenseRuleVerdict{}, UnifiedRadarBehaviorReport{})
	finalized := FinalizeUnifiedRadarVerdictContract("MintOne", verdict)
	if !finalized.Signed || finalized.Signature == "" {
		t.Fatalf("finalized verdict=%#v", finalized)
	}
	other := FinalizeUnifiedRadarVerdictContract("MintTwo", verdict)
	if finalized.Signature == other.Signature {
		t.Fatal("target-bound signatures must differ")
	}
}

func TestUnifiedRuntimeContractCarriesTriggeredRules(t *testing.T) {
	actor := ActorDefenseRuleVerdict{TriggeredRules: []ActorDefenseRuleHit{
		{RuleID: ActorRuleCompoundCreatorReuse, Title: "Creator reuse", Tier: "compounding", EvidenceStatus: "verified", GradeEffect: "compounding_input", Summary: "creator reused"},
		{RuleID: ActorRuleCompoundHolderReuse, Title: "Holder reuse", Tier: "compounding", EvidenceStatus: "observed", GradeEffect: "compounding_input", Summary: "holder reused"},
	}}
	verdict := FinalizeUnifiedRadarVerdictContract("MintOne", EvaluateUnifiedRadarVerdict("MintOne", actor, UnifiedRadarBehaviorReport{}))
	encoded, err := json.Marshal(verdict)
	if err != nil {
		t.Fatal(err)
	}
	var contract map[string]any
	if err := json.Unmarshal(encoded, &contract); err != nil {
		t.Fatal(err)
	}
	if contract["grade"] != "B" || contract["signed"] != true {
		t.Fatalf("contract=%s", encoded)
	}
	rules, ok := contract["triggered_rules"].([]any)
	if !ok || len(rules) != 2 {
		t.Fatalf("triggered_rules=%#v", contract["triggered_rules"])
	}
	evidence, ok := contract["evidence"].([]any)
	if !ok || len(evidence) != 2 {
		t.Fatalf("evidence=%#v", contract["evidence"])
	}
}

func TestUnifiedContractCountsMultipleC004GroupsAsOneRuleID(t *testing.T) {
	groups := []ActorDefenseRuleHit{
		{RuleID: ActorRuleCompoundRepeatedTransfer, Title: "Repeated transfer A", Tier: "compounding", EvidenceStatus: "verified", GradeEffect: "compounding_input", Count: 7, EvidenceKeys: []string{"a:1"}, Signatures: []string{"sig-a"}, Facts: map[string]any{"relation": "direct_sol_transfer_in", "counterpart_id": "WalletA"}},
		{RuleID: ActorRuleCompoundRepeatedTransfer, Title: "Repeated transfer B", Tier: "compounding", EvidenceStatus: "verified", GradeEffect: "compounding_input", Count: 8, EvidenceKeys: []string{"b:1"}, Signatures: []string{"sig-b"}, Facts: map[string]any{"relation": "direct_sol_transfer_in", "counterpart_id": "WalletB"}},
		{RuleID: ActorRuleCompoundRepeatedTransfer, Title: "Repeated transfer C", Tier: "compounding", EvidenceStatus: "observed", GradeEffect: "compounding_input", Count: 2, EvidenceKeys: []string{"c:1"}, Signatures: []string{"sig-c"}, Facts: map[string]any{"relation": "direct_token_transfer_out", "counterpart_id": "WalletC"}},
	}
	raw := UnifiedRadarVerdict{
		Grade: "B", Verdict: "compounding_rule", RulesetVersion: UnifiedRadarRulesetVersion,
		ActorRuleset: ActorDefenseRulesetVersion, TriggeredRules: groups,
		Signature: "koschei-unified:stale-grade-signature",
	}
	finalized := FinalizeUnifiedRadarVerdictContract("ActorWallet", raw)
	if finalized.Grade != "-" || finalized.Verdict != "single_observation" || !finalized.Signed {
		t.Fatalf("same rule ID groups inflated unified grade: %#v", finalized)
	}
	if len(finalized.TriggeredRules) != 3 {
		t.Fatalf("audit groups were removed: %#v", finalized.TriggeredRules)
	}
	if finalized.Signature == raw.Signature || !strings.HasPrefix(finalized.Signature, "koschei-unified:") {
		t.Fatalf("stale B signature survived normalization: %q", finalized.Signature)
	}
	if !unifiedDecisionContains(finalized.DecisionPath, "one distinct evidence-backed compounding rule id") {
		t.Fatalf("decision path does not explain distinct rule-ID counting: %#v", finalized.DecisionPath)
	}
}

func TestUnifiedMarshalNormalizesRawDuplicateRuleGrade(t *testing.T) {
	raw := UnifiedRadarVerdict{
		Grade: "B", Verdict: "compounding_rule", RulesetVersion: UnifiedRadarRulesetVersion,
		TriggeredRules: []ActorDefenseRuleHit{
			{RuleID: ActorRuleCompoundRepeatedTransfer, Tier: "compounding", EvidenceStatus: "verified", Summary: "group one"},
			{RuleID: ActorRuleCompoundRepeatedTransfer, Tier: "compounding", EvidenceStatus: "verified", Summary: "group two"},
		},
		Signature: "koschei-unified:stale",
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var contract map[string]any
	if err := json.Unmarshal(encoded, &contract); err != nil {
		t.Fatal(err)
	}
	if contract["grade"] != "-" || contract["verdict"] != "single_observation" {
		t.Fatalf("raw duplicate-rule grade leaked through serialization: %s", encoded)
	}
	if signature, _ := contract["signature"].(string); !strings.HasPrefix(signature, "koschei-unified-contract:") {
		t.Fatalf("changed serialized decision retained stale signature: %q", signature)
	}
}

func TestUnifiedContractAllowsC004PlusDistinctRuleIDToProduceB(t *testing.T) {
	verdict := FinalizeUnifiedRadarVerdictContract("ActorWallet", UnifiedRadarVerdict{
		RulesetVersion: UnifiedRadarRulesetVersion,
		TriggeredRules: []ActorDefenseRuleHit{
			{RuleID: ActorRuleCompoundRepeatedTransfer, Tier: "compounding", EvidenceStatus: "verified", Summary: "C004 group one"},
			{RuleID: ActorRuleCompoundRepeatedTransfer, Tier: "compounding", EvidenceStatus: "verified", Summary: "C004 group two"},
			{RuleID: UnifiedRuleVolumeLiquidityGap, Tier: "compounding", EvidenceStatus: "observed", Summary: "market gap"},
		},
	})
	if verdict.Grade != "B" || verdict.Verdict != "compounding_rule" || !verdict.Signed {
		t.Fatalf("two distinct rule IDs did not produce B: %#v", verdict)
	}
}

func unifiedDecisionContains(items []string, fragment string) bool {
	fragment = strings.ToLower(strings.TrimSpace(fragment))
	for _, item := range items {
		if strings.Contains(strings.ToLower(item), fragment) {
			return true
		}
	}
	return false
}

func TestStrictVerdictModeRequiresVerifiedCompoundingRules(t *testing.T) {
	t.Setenv("KOSCHEI_VERDICT_MODE", "strict")
	verdict := FinalizeUnifiedRadarVerdictContract("StrictMint", UnifiedRadarVerdict{
		RulesetVersion: UnifiedRadarRulesetVersion,
		TriggeredRules: []ActorDefenseRuleHit{
			{RuleID: ActorRuleCompoundCreatorReuse, Tier: "compounding", EvidenceStatus: "verified", Summary: "verified group"},
			{RuleID: UnifiedRuleVolumeLiquidityGap, Tier: "compounding", EvidenceStatus: "observed", Summary: "observed group"},
		},
	})
	if verdict.Grade != "-" || verdict.Verdict != "single_observation" {
		t.Fatalf("strict mode let OBSERVED evidence change grade: %#v", verdict)
	}
}

func TestEvidenceOnlyVerdictModePreservesSignedEvidenceAndWithholdsGrade(t *testing.T) {
	t.Setenv("KOSCHEI_VERDICT_MODE", "evidence_only")
	verdict := FinalizeUnifiedRadarVerdictContract("EvidenceMint", UnifiedRadarVerdict{
		RulesetVersion: UnifiedRadarRulesetVersion,
		TriggeredRules: []ActorDefenseRuleHit{
			{RuleID: ActorRuleCompoundCreatorReuse, Tier: "compounding", EvidenceStatus: "verified", Summary: "one"},
			{RuleID: UnifiedRuleVolumeLiquidityGap, Tier: "compounding", EvidenceStatus: "verified", Summary: "two"},
		},
	})
	if verdict.Grade != "-" || verdict.Verdict != "evidence_only" || !verdict.Signed || verdict.Signature == "" {
		t.Fatalf("evidence-only mode contract=%#v", verdict)
	}
}
