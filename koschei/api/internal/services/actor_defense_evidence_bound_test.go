package services

import "testing"

func TestEvidenceBoundActorRulesExcludeCounterOnlyCompoundingRule(t *testing.T) {
	track := ActorDefenseTrack{
		Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet",
		State: "correlated", RelatedActorCount: 1,
	}
	evidence := []ActorDefenseEvidenceRecord{{
		Relation: "direct_sol_transfer_out", VerificationStatus: "verified",
		EvidenceKey: "sig-one:0", Signature: "sig-one", OccurrenceCount: 6,
	}}

	verdict := EvaluateEvidenceBoundActorDefenseRules(track, evidence)
	if verdict.Grade != "-" || verdict.Verdict != "single_observation" || verdict.Signed {
		t.Fatalf("counter-only compounding observation issued a grade: %#v", verdict)
	}
	if actorRulePresent(verdict.TriggeredRules, ActorRuleCompoundRelatedActorReuse) {
		t.Fatalf("evidence-less %s remained grade-changing", ActorRuleCompoundRelatedActorReuse)
	}
	if !actorRulePresent(verdict.WatchFlags, ActorRuleCompoundRelatedActorReuse) {
		t.Fatalf("evidence-less %s must remain visible as watch context", ActorRuleCompoundRelatedActorReuse)
	}
}

func TestEvidenceBoundActorRulesBindCrossTokenEvidenceAndProduceB(t *testing.T) {
	track := ActorDefenseTrack{
		Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet",
		State: "correlated", RelatedActorCount: 1,
	}
	evidence := []ActorDefenseEvidenceRecord{
		{
			Relation: "direct_sol_transfer_out", VerificationStatus: "verified",
			EvidenceKey: "sig-one:0", Signature: "sig-one", OccurrenceCount: 6,
		},
		{
			Relation: "cross_token_related_actor", VerificationStatus: "observed",
			EvidenceKey: "cross-token:holder-one", Signature: "sig-two",
		},
	}

	verdict := EvaluateEvidenceBoundActorDefenseRules(track, evidence)
	if verdict.Grade != "B" || verdict.Verdict != "compounding_rule" || !verdict.Signed || verdict.Signature == "" {
		t.Fatalf("evidence-backed compounding verdict=%#v", verdict)
	}
	for _, hit := range verdict.TriggeredRules {
		if len(hit.EvidenceKeys) == 0 {
			t.Fatalf("grade-changing rule lacks evidence keys: %#v", hit)
		}
	}
}

func TestEvidenceBoundActorRulesDoNotGradeFromTrackCountersAlone(t *testing.T) {
	track := ActorDefenseTrack{
		Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet",
		State: "correlated", CreatedTokenCount: 2, DominantHolderTokenCount: 2,
	}
	verdict := EvaluateEvidenceBoundActorDefenseRules(track, nil)
	if verdict.Grade != "-" || verdict.Signed || len(verdict.TriggeredRules) != 0 {
		t.Fatalf("track counters without canonical evidence issued a grade: %#v", verdict)
	}
	if len(verdict.WatchFlags) != 2 {
		t.Fatalf("expected two visible watch flags, got %#v", verdict.WatchFlags)
	}
}
