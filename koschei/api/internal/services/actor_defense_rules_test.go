package services

import (
	"testing"
	"time"
)

func TestActorRulesVerifiedCreatorLiquidityRemovalCapsAtD(t *testing.T) {
	track := ActorDefenseTrack{
		Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet",
		State: "correlated", CreatedTokenCount: 2, DominantHolderTokenCount: 2,
	}
	evidence := []ActorDefenseEvidenceRecord{{
		Relation: "liquidity_remove_activity", VerificationStatus: "verified",
		EvidenceKey: "sig-one:remove", Signature: "sig-one", ObservedAt: time.Unix(1700000000, 0).UTC(),
		Metadata: map[string]any{"actor_signed": true},
	}}
	verdict := EvaluateActorDefenseRules(track, evidence)
	if verdict.Grade != "D" || verdict.Verdict != "hard_trigger" {
		t.Fatalf("verdict=%#v", verdict)
	}
	if !verdict.Signed || verdict.Signature == "" {
		t.Fatal("deterministic hard-trigger verdict must be signed")
	}
	if !actorRulePresent(verdict.TriggeredRules, ActorRuleHardCreatorLiquidityRemoval) {
		t.Fatalf("missing %s", ActorRuleHardCreatorLiquidityRemoval)
	}
	if !actorRulePresent(verdict.TriggeredRules, ActorRuleCompoundCreatorReuse) || !actorRulePresent(verdict.TriggeredRules, ActorRuleCompoundHolderReuse) {
		t.Fatal("supporting compounding rules must remain visible")
	}
}

func TestActorRulesVerifiedCreatorHolderFundingCapsAtD(t *testing.T) {
	track := ActorDefenseTrack{
		Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet",
		CreatedTokenCount: 2,
	}
	evidence := []ActorDefenseEvidenceRecord{{
		Relation: "direct_sol_transfer_out", VerificationStatus: "verified",
		EvidenceKey: "sig-two:0", Signature: "sig-two", CounterpartKind: "wallet", CounterpartID: "HolderWallet",
		AmountNative: 1,
		Metadata:     map[string]any{"actor_signed": true, "known_related_actor": true},
	}}
	verdict := EvaluateActorDefenseRules(track, evidence)
	if verdict.Grade != "D" || !actorRulePresent(verdict.TriggeredRules, ActorRuleHardCreatorHolderFunding) {
		t.Fatalf("verdict=%#v", verdict)
	}
}

func TestActorRulesPossibleDustCannotBecomeCreatorHolderFunding(t *testing.T) {
	track := ActorDefenseTrack{
		Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet",
		CreatedTokenCount: 1,
	}
	evidence := []ActorDefenseEvidenceRecord{{
		Relation: "direct_sol_transfer_out", VerificationStatus: "verified",
		EvidenceKey: "dust-out:0", Signature: "dust-out", CounterpartKind: "wallet", CounterpartID: "HolderWallet",
		AmountNative: ActorPossibleDustNativeSOLMax,
		Metadata:     map[string]any{"actor_signed": true, "known_related_actor": true},
	}}
	verdict := EvaluateActorDefenseRules(track, evidence)
	if actorRulePresent(verdict.TriggeredRules, ActorRuleHardCreatorHolderFunding) {
		t.Fatalf("possible dust became hard funding proof: %#v", verdict)
	}
	if !actorRulePresent(verdict.WatchFlags, ActorRuleWatchPossibleDust) {
		t.Fatalf("possible dust watch flag missing: %#v", verdict)
	}
}

func TestActorRulesPreviousTokenIncidentCapsAtC(t *testing.T) {
	track := ActorDefenseTrack{Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet"}
	evidence := []ActorDefenseEvidenceRecord{{
		Relation: "prior_token_liquidity_removal", VerificationStatus: "verified",
		EvidenceKey: "old-token-sig:0", Signature: "old-token-sig",
	}}
	verdict := EvaluateActorDefenseRules(track, evidence)
	if verdict.Grade != "C" || verdict.Verdict != "hard_trigger" {
		t.Fatalf("verdict=%#v", verdict)
	}
}

func TestActorRulesTwoObservedCompoundingRulesProduceB(t *testing.T) {
	track := ActorDefenseTrack{
		Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet",
		State: "correlated", CreatedTokenCount: 2, DominantHolderTokenCount: 2,
	}
	verdict := EvaluateActorDefenseRules(track, nil)
	if verdict.Grade != "B" || verdict.Verdict != "compounding_rule" {
		t.Fatalf("verdict=%#v", verdict)
	}
	if !verdict.Signed {
		t.Fatal("deterministic compounding verdict must be signed")
	}
}

func TestActorRulesC004RequiresTwoDistinctSignaturesForSameRelation(t *testing.T) {
	track := ActorDefenseTrack{Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet"}
	evidence := []ActorDefenseEvidenceRecord{
		{Relation: "direct_sol_transfer_out", VerificationStatus: "observed", CounterpartKind: "wallet", CounterpartID: "Counterparty", EvidenceKey: "sig-a:0", Signature: "sig-a", AmountNative: 1},
		{Relation: "direct_sol_transfer_out", VerificationStatus: "observed", CounterpartKind: "wallet", CounterpartID: "Counterparty", EvidenceKey: "sig-b:0", Signature: "sig-b", AmountNative: 2},
	}
	verdict := EvaluateActorDefenseRules(track, evidence)
	hit, ok := actorRuleFind(verdict.TriggeredRules, ActorRuleCompoundRepeatedTransfer)
	if !ok {
		t.Fatalf("C004 missing: %#v", verdict)
	}
	if hit.Count != 2 || len(hit.Signatures) != 2 {
		t.Fatalf("C004 count/signatures inflated or missing: %#v", hit)
	}
	if verdict.Grade != "-" || verdict.Verdict != "single_observation" {
		t.Fatalf("one distinct compounding rule must not issue a grade: %#v", verdict)
	}
}

func TestActorRulesC004DedupesInstructionRowsFromOneSignature(t *testing.T) {
	track := ActorDefenseTrack{Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet"}
	evidence := []ActorDefenseEvidenceRecord{
		{Relation: "direct_sol_transfer_out", VerificationStatus: "observed", CounterpartKind: "wallet", CounterpartID: "Counterparty", EvidenceKey: "same-sig:0", Signature: "same-sig", AmountNative: 1},
		{Relation: "direct_sol_transfer_out", VerificationStatus: "observed", CounterpartKind: "wallet", CounterpartID: "Counterparty", EvidenceKey: "same-sig:1", Signature: "same-sig", AmountNative: 2},
		{Relation: "direct_token_transfer_in", VerificationStatus: "observed", CounterpartKind: "wallet", CounterpartID: "OtherCounterparty", EvidenceKey: "same-sig:2", Signature: "same-sig", TokenMint: "Mint", TokenAmount: 100},
	}
	verdict := EvaluateActorDefenseRules(track, evidence)
	if actorRulePresent(verdict.TriggeredRules, ActorRuleCompoundRepeatedTransfer) {
		t.Fatalf("one transaction signature was manufactured into recurrence: %#v", verdict)
	}
}

func TestActorRulesPossibleDustStaysWatchOnlyAndDoesNotTriggerC004(t *testing.T) {
	track := ActorDefenseTrack{Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet"}
	evidence := []ActorDefenseEvidenceRecord{
		{Relation: "direct_sol_transfer_in", VerificationStatus: "observed", CounterpartKind: "wallet", CounterpartID: "4qcDOne", EvidenceKey: "dust-a:0", Signature: "dust-a", AmountNative: 0.000001, Metadata: map[string]any{"actor_signed": false}},
		{Relation: "direct_sol_transfer_in", VerificationStatus: "observed", CounterpartKind: "wallet", CounterpartID: "4qcDOne", EvidenceKey: "dust-b:0", Signature: "dust-b", AmountNative: 0.00001, Metadata: map[string]any{"actor_signed": false}},
	}
	verdict := EvaluateActorDefenseRules(track, evidence)
	if actorRulePresent(verdict.TriggeredRules, ActorRuleCompoundRepeatedTransfer) {
		t.Fatalf("possible dust triggered C004: %#v", verdict)
	}
	hit, ok := actorRuleFind(verdict.WatchFlags, ActorRuleWatchPossibleDust)
	if !ok || hit.Count != 2 {
		t.Fatalf("dust watch flag=%#v verdict=%#v", hit, verdict)
	}
	if verdict.Grade != "-" || verdict.Verdict != "watch_only" || verdict.Signed {
		t.Fatalf("dust changed the grade: %#v", verdict)
	}
}

func TestActorRulesSingleObservationDoesNotIssueGrade(t *testing.T) {
	track := ActorDefenseTrack{CreatedTokenCount: 2}
	verdict := EvaluateActorDefenseRules(track, nil)
	if verdict.Grade != "-" || verdict.Verdict != "single_observation" || verdict.Signed {
		t.Fatalf("verdict=%#v", verdict)
	}
}

func TestActorRulesInferredIsWatchOnly(t *testing.T) {
	track := ActorDefenseTrack{Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet"}
	evidence := []ActorDefenseEvidenceRecord{{
		Relation: "possible_shared_funder", VerificationStatus: "inferred", EvidenceKey: "inferred-one",
	}}
	verdict := EvaluateActorDefenseRules(track, evidence)
	if verdict.Grade != "-" || verdict.Verdict != "watch_only" || verdict.Signed {
		t.Fatalf("verdict=%#v", verdict)
	}
	if len(verdict.WatchFlags) != 1 || verdict.WatchFlags[0].EvidenceStatus != "inferred" {
		t.Fatalf("watch_flags=%#v", verdict.WatchFlags)
	}
}

func TestActorRulesUnverifiedIsExcluded(t *testing.T) {
	track := ActorDefenseTrack{Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet"}
	evidence := []ActorDefenseEvidenceRecord{{
		Relation: "direct_sol_transfer_out", VerificationStatus: "unverified", EvidenceKey: "unverified-one",
	}}
	verdict := EvaluateActorDefenseRules(track, evidence)
	if verdict.Grade != "-" || len(verdict.TriggeredRules) != 0 || len(verdict.WatchFlags) != 0 {
		t.Fatalf("verdict=%#v", verdict)
	}
	if verdict.ExcludedUnverifiedEvidence != 1 {
		t.Fatalf("excluded=%d", verdict.ExcludedUnverifiedEvidence)
	}
}

func TestActorRuleSignatureIsDeterministic(t *testing.T) {
	track := ActorDefenseTrack{
		Network: "solana-mainnet", TargetKind: "wallet", TargetID: "CaseSensitiveWallet",
		State: "correlated", CreatedTokenCount: 2, DominantHolderTokenCount: 2,
	}
	first := EvaluateActorDefenseRules(track, nil)
	time.Sleep(time.Millisecond)
	second := EvaluateActorDefenseRules(track, nil)
	if first.Signature == "" || first.Signature != second.Signature {
		t.Fatalf("signatures are not deterministic: %q %q", first.Signature, second.Signature)
	}
}

func TestActorRulesNoEvidenceIsNotAGrade(t *testing.T) {
	verdict := EvaluateActorDefenseRules(ActorDefenseTrack{}, nil)
	if verdict.Grade != "-" || verdict.Verdict != "no_grade_trigger" {
		t.Fatalf("absence of evidence became a safe grade: %#v", verdict)
	}
}

func actorRulePresent(items []ActorDefenseRuleHit, id string) bool {
	_, ok := actorRuleFind(items, id)
	return ok
}

func actorRuleFind(items []ActorDefenseRuleHit, id string) (ActorDefenseRuleHit, bool) {
	for _, item := range items {
		if item.RuleID == id {
			return item, true
		}
	}
	return ActorDefenseRuleHit{}, false
}
