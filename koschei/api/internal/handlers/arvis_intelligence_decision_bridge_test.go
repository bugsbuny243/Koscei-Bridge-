package handlers

import (
	"strings"
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestApplyArvisIntelligenceDecisionLinksVerifiedHardTrigger(t *testing.T) {
	subject := services.ClassifyIntelligenceSubject("So11111111111111111111111111111111111111112", "solana-mainnet")
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{subject}, time.Unix(1, 0).UTC())
	investigation.Evidence = append(investigation.Evidence, services.IntelligenceEvidence{
		ID:              "arvis_funding:creator-holder",
		SubjectID:       subject.ID,
		ChainFamily:     subject.ChainFamily,
		Chain:           subject.Chain,
		Network:         subject.Network,
		Status:          services.IntelligenceEvidenceVerified,
		TransactionHash: "sig-funding-1",
		Attributes: map[string]any{
			"evidence_key": "creator-holder-funding:1",
		},
	})
	final := services.UnifiedRadarVerdict{
		Grade:   "D",
		Verdict: "hard_trigger",
		Signed:  true,
		TriggeredRules: []services.ActorDefenseRuleHit{{
			RuleID:         services.ActorRuleHardCreatorHolderFunding,
			Tier:           "hard_trigger",
			EvidenceStatus: services.IntelligenceEvidenceVerified,
			GradeEffect:    "hard_cap_D",
			EvidenceKeys:   []string{"creator-holder-funding:1"},
			Signatures:     []string{"sig-funding-1"},
		}},
		DecisionPath: []string{"VERIFIED hard trigger applied."},
	}

	applyArvisIntelligenceDecision(&investigation, final)

	if investigation.Decision.Status != services.IntelligenceEvidenceVerified {
		t.Fatalf("decision status=%q", investigation.Decision.Status)
	}
	if investigation.Decision.Action != "review_signed_verdict" || investigation.Decision.Confidence != 1 {
		t.Fatalf("decision=%#v", investigation.Decision)
	}
	if len(investigation.Decision.EvidenceRefs) != 1 || investigation.Decision.EvidenceRefs[0] != "arvis_funding:creator-holder" {
		t.Fatalf("evidence refs=%#v", investigation.Decision.EvidenceRefs)
	}
}

func TestApplyArvisIntelligenceDecisionFailsClosedWhenDeterminingRuleIsUnlinked(t *testing.T) {
	subject := services.ClassifyIntelligenceSubject("So11111111111111111111111111111111111111112", "solana-mainnet")
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{subject}, time.Unix(1, 0).UTC())
	final := services.UnifiedRadarVerdict{
		Grade:   "D",
		Verdict: "hard_trigger",
		Signed:  true,
		TriggeredRules: []services.ActorDefenseRuleHit{{
			RuleID:         services.ActorRuleHardCreatorHolderFunding,
			Tier:           "hard_trigger",
			EvidenceStatus: services.IntelligenceEvidenceVerified,
			GradeEffect:    "hard_cap_D",
			EvidenceKeys:   []string{"missing-key"},
		}},
	}

	applyArvisIntelligenceDecision(&investigation, final)

	if investigation.Decision.Status != services.IntelligenceEvidenceUnverified || investigation.Decision.Action != "investigate" || investigation.Decision.Confidence != 0 {
		t.Fatalf("decision=%#v", investigation.Decision)
	}
	if !strings.Contains(investigation.Decision.Summary, "withheld") {
		t.Fatalf("summary=%q", investigation.Decision.Summary)
	}
	if len(investigation.Decision.Reasons) == 0 || !strings.Contains(investigation.Decision.Reasons[len(investigation.Decision.Reasons)-1], services.ActorRuleHardCreatorHolderFunding) {
		t.Fatalf("reasons=%#v", investigation.Decision.Reasons)
	}
}

func TestApplyArvisIntelligenceDecisionUsesOnlyGradeDeterminingHardRules(t *testing.T) {
	subject := services.ClassifyIntelligenceSubject("So11111111111111111111111111111111111111112", "solana-mainnet")
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{subject}, time.Unix(1, 0).UTC())
	investigation.Evidence = append(investigation.Evidence, services.IntelligenceEvidence{
		ID:              "arvis_funding:hard",
		SubjectID:       subject.ID,
		ChainFamily:     subject.ChainFamily,
		Chain:           subject.Chain,
		Network:         subject.Network,
		Status:          services.IntelligenceEvidenceVerified,
		TransactionHash: "sig-hard",
	})
	final := services.UnifiedRadarVerdict{
		Grade:   "D",
		Verdict: "hard_trigger",
		Signed:  true,
		TriggeredRules: []services.ActorDefenseRuleHit{
			{
				RuleID:         services.ActorRuleHardCreatorHolderFunding,
				Tier:           "hard_trigger",
				EvidenceStatus: services.IntelligenceEvidenceVerified,
				GradeEffect:    "hard_cap_D",
				Signatures:     []string{"sig-hard"},
			},
			{
				RuleID:         services.ActorRuleCompoundCreatorReuse,
				Tier:           "compounding",
				EvidenceStatus: services.IntelligenceEvidenceObserved,
				GradeEffect:    "compounding_input",
				EvidenceKeys:   []string{"supporting-key-without-canonical-link"},
			},
		},
	}

	applyArvisIntelligenceDecision(&investigation, final)

	if investigation.Decision.Status != services.IntelligenceEvidenceVerified {
		t.Fatalf("supporting rule blocked hard decision: %#v", investigation.Decision)
	}
}

func TestApplyArvisIntelligenceDecisionLinksObservedCompoundingRules(t *testing.T) {
	subject := services.ClassifyIntelligenceSubject("So11111111111111111111111111111111111111112", "solana-mainnet")
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{subject}, time.Unix(1, 0).UTC())
	investigation.Evidence = append(investigation.Evidence,
		services.IntelligenceEvidence{
			ID:          "arvis_behavior:URD-C001:key-a",
			SubjectID:   subject.ID,
			ChainFamily: subject.ChainFamily,
			Chain:       subject.Chain,
			Network:     subject.Network,
			Status:      services.IntelligenceEvidenceObserved,
			Attributes:  map[string]any{"rule_id": services.UnifiedRuleVolumeLiquidityGap, "evidence_keys": []string{"key-a"}},
		},
		services.IntelligenceEvidence{
			ID:          "arvis_behavior:URD-C002:key-b",
			SubjectID:   subject.ID,
			ChainFamily: subject.ChainFamily,
			Chain:       subject.Chain,
			Network:     subject.Network,
			Status:      services.IntelligenceEvidenceObserved,
			Attributes:  map[string]any{"rule_id": services.UnifiedRuleHolderLiquidityPressure, "evidence_keys": []string{"key-b"}},
		},
	)
	final := services.UnifiedRadarVerdict{
		Grade:   "D",
		Verdict: "compounding_rule",
		Signed:  true,
		TriggeredRules: []services.ActorDefenseRuleHit{
			{RuleID: services.UnifiedRuleVolumeLiquidityGap, Tier: "compounding", EvidenceStatus: services.IntelligenceEvidenceObserved, GradeEffect: "compounding_input", EvidenceKeys: []string{"key-a"}},
			{RuleID: services.UnifiedRuleHolderLiquidityPressure, Tier: "compounding", EvidenceStatus: services.IntelligenceEvidenceObserved, GradeEffect: "compounding_input", EvidenceKeys: []string{"key-b"}},
		},
	}

	applyArvisIntelligenceDecision(&investigation, final)

	if investigation.Decision.Status != services.IntelligenceEvidenceObserved {
		t.Fatalf("decision status=%q", investigation.Decision.Status)
	}
	if len(investigation.Decision.EvidenceRefs) != 2 {
		t.Fatalf("evidence refs=%#v", investigation.Decision.EvidenceRefs)
	}
}

func TestApplyArvisIntelligenceDecisionDoesNotTurnNoGradeIntoApproval(t *testing.T) {
	subject := services.ClassifyIntelligenceSubject("So11111111111111111111111111111111111111112", "solana-mainnet")
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{subject}, time.Unix(1, 0).UTC())
	final := services.UnifiedRadarVerdict{Grade: "-", Verdict: "no_grade_trigger", Signed: true}

	applyArvisIntelligenceDecision(&investigation, final)

	if investigation.Decision.Status != services.IntelligenceEvidenceUnverified || investigation.Decision.Action != "investigate" {
		t.Fatalf("no-grade result became approval: %#v", investigation.Decision)
	}
}
