package services

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUnifiedMarshalPreservesFinalizedTargetBoundSignature(t *testing.T) {
	finalized := FinalizeUnifiedRadarVerdictContract("TargetMint111", UnifiedRadarVerdict{
		RulesetVersion: UnifiedRadarRulesetVersion,
		ActorRuleset:   ActorDefenseRulesetVersion,
		TriggeredRules: []ActorDefenseRuleHit{
			{RuleID: ActorRuleCompoundCreatorReuse, Tier: "compounding", EvidenceStatus: "verified", Summary: "creator reuse"},
			{RuleID: UnifiedRuleVolumeLiquidityGap, Tier: "compounding", EvidenceStatus: "observed", Summary: "market gap"},
		},
	})
	if !finalized.Signed || !strings.HasPrefix(finalized.Signature, "koschei-unified:") {
		t.Fatalf("expected finalized target-bound signature, got %q", finalized.Signature)
	}

	raw, err := json.Marshal(finalized)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(payload["signature"].(string)); got != finalized.Signature {
		t.Fatalf("JSON changed finalized signature: got %q want %q", got, finalized.Signature)
	}
	if got := strings.TrimSpace(payload["grade"].(string)); got != finalized.Grade {
		t.Fatalf("JSON changed finalized grade: got %q want %q", got, finalized.Grade)
	}
	if got := strings.TrimSpace(payload["verdict"].(string)); got != finalized.Verdict {
		t.Fatalf("JSON changed finalized verdict: got %q want %q", got, finalized.Verdict)
	}
}

func TestUnifiedMarshalDropsStaleSignatureWhenDecisionNormalizes(t *testing.T) {
	stale := UnifiedRadarVerdict{
		Grade:          "B",
		Verdict:        "compounding_rule",
		RulesetVersion: UnifiedRadarRulesetVersion,
		TriggeredRules: []ActorDefenseRuleHit{
			{RuleID: ActorRuleCompoundRepeatedTransfer, Tier: "compounding", EvidenceStatus: "verified", Summary: "group one"},
			{RuleID: ActorRuleCompoundRepeatedTransfer, Tier: "compounding", EvidenceStatus: "verified", Summary: "group two"},
		},
		Signed:    true,
		Signature: "koschei-unified:must-not-survive",
	}

	raw, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(payload["grade"].(string)); got != "-" {
		t.Fatalf("expected normalized no-grade state, got %q", got)
	}
	if got := strings.TrimSpace(payload["verdict"].(string)); got != "single_observation" {
		t.Fatalf("expected normalized single observation, got %q", got)
	}
	got := strings.TrimSpace(payload["signature"].(string))
	if got == stale.Signature {
		t.Fatalf("stale target-bound signature survived decision change: %q", got)
	}
	if !strings.HasPrefix(got, "koschei-unified-contract:") {
		t.Fatalf("expected contract-state fallback after decision change, got %q", got)
	}
}
