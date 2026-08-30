package services

import "testing"

func TestEvidenceBoundActorRulesBindCanonicalDominantHolderRowsAcrossDistinctMints(t *testing.T) {
	track := ActorDefenseTrack{
		Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet",
		CreatedTokenCount: 2, DominantHolderTokenCount: 2,
	}
	evidence := []ActorDefenseEvidenceRecord{
		{Relation: "created_token", VerificationStatus: "verified", EvidenceKey: "create-one", Signature: "create-sig-one", TokenMint: "MintOne"},
		{Relation: "created_token", VerificationStatus: "verified", EvidenceKey: "create-two", Signature: "create-sig-two", TokenMint: "MintTwo"},
		{Relation: "dominant_holder_of", VerificationStatus: "observed", EvidenceKey: "holder-one", TokenMint: "MintOne"},
		{Relation: "dominant_holder_of", VerificationStatus: "verified", EvidenceKey: "holder-two", TokenMint: "MintTwo"},
	}

	verdict := EvaluateEvidenceBoundActorDefenseRules(track, evidence)
	if verdict.Grade != "B" || verdict.Verdict != "compounding_rule" || !verdict.Signed || verdict.Signature == "" {
		t.Fatalf("canonical creator + holder reuse evidence should produce signed B: %#v", verdict)
	}
	if !actorRulePresent(verdict.TriggeredRules, ActorRuleCompoundHolderReuse) {
		t.Fatalf("%s should remain grade-changing when canonical holder evidence covers both mints: %#v", ActorRuleCompoundHolderReuse, verdict)
	}
	for _, hit := range verdict.TriggeredRules {
		if hit.RuleID == ActorRuleCompoundHolderReuse && len(hit.EvidenceKeys) != 2 {
			t.Fatalf("%s evidence keys=%v want two canonical holder rows", ActorRuleCompoundHolderReuse, hit.EvidenceKeys)
		}
	}
}

func TestEvidenceBoundActorRulesRejectSameMintHolderRowsAsReuseProof(t *testing.T) {
	track := ActorDefenseTrack{
		Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet",
		DominantHolderTokenCount: 2,
	}
	evidence := []ActorDefenseEvidenceRecord{
		{Relation: "dominant_holder_of", VerificationStatus: "verified", EvidenceKey: "holder-one", TokenMint: "MintOne"},
		{Relation: "dominant_holder_of", VerificationStatus: "observed", EvidenceKey: "holder-two", TokenMint: "MintOne"},
	}

	verdict := EvaluateEvidenceBoundActorDefenseRules(track, evidence)
	if verdict.Grade != "-" || verdict.Verdict != "watch_only" || !verdict.Signed || verdict.Signature == "" {
		t.Fatalf("same-mint holder rows must fail closed to signed WITHHOLD: %#v", verdict)
	}
	if actorRulePresent(verdict.TriggeredRules, ActorRuleCompoundHolderReuse) {
		t.Fatalf("same-mint rows must not bind %s as grade-changing evidence", ActorRuleCompoundHolderReuse)
	}
	if !actorRulePresent(verdict.WatchFlags, ActorRuleCompoundHolderReuse) {
		t.Fatalf("unproven %s must remain visible as watch context", ActorRuleCompoundHolderReuse)
	}
}

func TestEvidenceBoundActorRulesRequireEvidenceCoverageForClaimedHolderCount(t *testing.T) {
	track := ActorDefenseTrack{
		Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet",
		DominantHolderTokenCount: 3,
	}
	evidence := []ActorDefenseEvidenceRecord{
		{Relation: "dominant_holder_of", VerificationStatus: "verified", EvidenceKey: "holder-one", TokenMint: "MintOne"},
		{Relation: "dominant_holder_of", VerificationStatus: "verified", EvidenceKey: "holder-two", TokenMint: "MintTwo"},
	}

	verdict := EvaluateEvidenceBoundActorDefenseRules(track, evidence)
	if actorRulePresent(verdict.TriggeredRules, ActorRuleCompoundHolderReuse) {
		t.Fatalf("partial distinct-mint coverage must not bind %s: %#v", ActorRuleCompoundHolderReuse, verdict)
	}
	if !actorRulePresent(verdict.WatchFlags, ActorRuleCompoundHolderReuse) {
		t.Fatalf("partial holder coverage must remain visible as watch context: %#v", verdict)
	}
}
