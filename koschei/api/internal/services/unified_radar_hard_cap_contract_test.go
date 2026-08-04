package services

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUnifiedContractPreservesVerifiedHardCapGradeEffect(t *testing.T) {
	raw := UnifiedRadarVerdict{
		Grade:          "B",
		Verdict:        "compounding_rule",
		RulesetVersion: UnifiedRadarRulesetVersionV110,
		ActorRuleset:   ActorDefenseRulesetVersion,
		TriggeredRules: []ActorDefenseRuleHit{
			{
				RuleID:         ActorRuleCompoundRepeatedTransfer,
				Title:          "Repeated transfer group one",
				Tier:           "compounding",
				EvidenceStatus: "verified",
				GradeEffect:    "compounding_input",
				EvidenceKeys:   []string{"group:one"},
			},
			{
				RuleID:         ActorRuleCompoundRepeatedTransfer,
				Title:          "Repeated transfer group two",
				Tier:           "compounding",
				EvidenceStatus: "verified",
				GradeEffect:    "compounding_input",
				EvidenceKeys:   []string{"group:two"},
			},
			{
				RuleID:         UnifiedRuleOwnerConcentration,
				Title:          "Owner-resolved dominant concentration",
				Tier:           "compounding",
				EvidenceStatus: "verified",
				GradeEffect:    "hard_cap_F",
				EvidenceKeys:   []string{"owner:dominant"},
			},
		},
		Signed:    true,
		Signature: "koschei-unified:stale-b",
	}

	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal hard-cap verdict: %v", err)
	}
	var contract map[string]any
	if err := json.Unmarshal(encoded, &contract); err != nil {
		t.Fatalf("decode hard-cap contract: %v", err)
	}
	if contract["grade"] != "F" || contract["verdict"] != "hard_trigger" {
		t.Fatalf("hard cap was rewritten during serialization: %s", encoded)
	}
	if signature, _ := contract["signature"].(string); !strings.HasPrefix(signature, "koschei-unified-contract:") {
		t.Fatalf("changed hard-cap decision retained stale signature: %q", signature)
	}
	decision, _ := contract["decision_path"].([]any)
	foundHardCap := false
	for _, item := range decision {
		if strings.Contains(strings.ToLower(item.(string)), "hard-trigger ceiling applied: grade f") {
			foundHardCap = true
			break
		}
	}
	if !foundHardCap {
		t.Fatalf("hard-cap decision path missing: %#v", decision)
	}
}

func TestFinalizeUnifiedContractPreservesV120HardCapAndRuleset(t *testing.T) {
	raw := UnifiedRadarVerdict{
		Grade:          "D",
		Verdict:        "hard_trigger",
		RulesetVersion: UnifiedRadarRulesetVersionV120,
		ActorRuleset:   ActorDefenseRulesetVersion,
		TriggeredRules: []ActorDefenseRuleHit{
			{
				RuleID:         UnifiedRuleCrossTokenCreatorHolderTransfer,
				Title:          "Cross-token creator to dominant-holder transfer",
				Tier:           "compounding",
				EvidenceStatus: "verified",
				GradeEffect:    "hard_cap_D",
				EvidenceKeys:   []string{"creator-holder-transfer:signature"},
				Signatures:     []string{"signature"},
			},
		},
	}

	finalized := FinalizeUnifiedRadarVerdictContract("MintV120", raw)
	if finalized.Grade != "D" || finalized.Verdict != "hard_trigger" {
		t.Fatalf("v1.2 hard cap changed: %#v", finalized)
	}
	if finalized.RulesetVersion != UnifiedRadarRulesetVersionV120 {
		t.Fatalf("v1.2 ruleset downgraded: %q", finalized.RulesetVersion)
	}
	if !finalized.Signed || !strings.HasPrefix(finalized.Signature, "koschei-unified:") {
		t.Fatalf("v1.2 verdict was not target-bound: %#v", finalized)
	}
}
