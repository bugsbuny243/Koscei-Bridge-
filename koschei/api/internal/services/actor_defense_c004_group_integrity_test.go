package services

import "testing"

func TestActorRulesC004PreservesEachRelationCounterpartGroup(t *testing.T) {
	track := ActorDefenseTrack{
		Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet",
	}
	evidence := []ActorDefenseEvidenceRecord{
		{Relation: "direct_sol_transfer_in", VerificationStatus: "verified", CounterpartKind: "wallet", CounterpartID: "CounterpartyA", EvidenceKey: "sig-a1:0", Signature: "sig-a1", AmountNative: 1},
		{Relation: "direct_sol_transfer_in", VerificationStatus: "verified", CounterpartKind: "wallet", CounterpartID: "CounterpartyA", EvidenceKey: "sig-a2:0", Signature: "sig-a2", AmountNative: 2},
		{Relation: "direct_sol_transfer_in", VerificationStatus: "verified", CounterpartKind: "wallet", CounterpartID: "CounterpartyB", EvidenceKey: "sig-b1:0", Signature: "sig-b1", AmountNative: 3},
		{Relation: "direct_sol_transfer_in", VerificationStatus: "verified", CounterpartKind: "wallet", CounterpartID: "CounterpartyB", EvidenceKey: "sig-b2:0", Signature: "sig-b2", AmountNative: 4},
		{Relation: "direct_token_transfer_in", VerificationStatus: "verified", CounterpartKind: "wallet", CounterpartID: "CounterpartyB", EvidenceKey: "sig-c1:0", Signature: "sig-c1", TokenMint: "MintA", TokenAmount: 10},
		{Relation: "direct_token_transfer_in", VerificationStatus: "verified", CounterpartKind: "wallet", CounterpartID: "CounterpartyB", EvidenceKey: "sig-c2:0", Signature: "sig-c2", TokenMint: "MintA", TokenAmount: 20},
	}

	verdict := EvaluateActorDefenseRules(track, evidence)
	hits := actorRuleTestHits(verdict.TriggeredRules, ActorRuleCompoundRepeatedTransfer)
	if len(hits) != 3 {
		t.Fatalf("C004 groups collapsed: %#v", hits)
	}
	expected := []struct {
		relation    string
		counterpart string
	}{
		{relation: "direct_sol_transfer_in", counterpart: "CounterpartyA"},
		{relation: "direct_sol_transfer_in", counterpart: "CounterpartyB"},
		{relation: "direct_token_transfer_in", counterpart: "CounterpartyB"},
	}
	for index, hit := range hits {
		if hit.Count != 2 || len(hit.Signatures) != 2 {
			t.Fatalf("group %d count/signatures=%#v", index, hit)
		}
		if got := actorRuleFactString(hit.Facts, "relation"); got != expected[index].relation {
			t.Fatalf("group %d relation=%q want %q", index, got, expected[index].relation)
		}
		if got := actorRuleFactString(hit.Facts, "counterpart_id"); got != expected[index].counterpart {
			t.Fatalf("group %d counterpart=%q want %q", index, got, expected[index].counterpart)
		}
		if got, ok := hit.Facts["distinct_signature_count"].(int); !ok || got != hit.Count {
			t.Fatalf("group %d facts/count mismatch: %#v", index, hit)
		}
	}
	if verdict.Grade != "-" || verdict.Verdict != "single_observation" {
		t.Fatalf("multiple C004 evidence groups became multiple rules: %#v", verdict)
	}

	bound := EvaluateEvidenceBoundActorDefenseRules(track, evidence)
	if bound.Grade != "-" || bound.Verdict != "single_observation" || !bound.Signed || bound.Signature == "" {
		t.Fatalf("evidence-bound C004 groups inflated grade: %#v", bound)
	}
	if got := len(actorRuleTestHits(bound.TriggeredRules, ActorRuleCompoundRepeatedTransfer)); got != 3 {
		t.Fatalf("evidence-bound C004 groups=%d want 3", got)
	}
	repeat := EvaluateEvidenceBoundActorDefenseRules(track, evidence)
	if repeat.Signature != bound.Signature {
		t.Fatalf("grouped C004 signature is not deterministic: %q != %q", bound.Signature, repeat.Signature)
	}
}

func TestActorRulesDistinctC004AndCreatorReuseCanProduceB(t *testing.T) {
	track := ActorDefenseTrack{
		Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet",
		CreatedTokenCount: 2,
	}
	evidence := []ActorDefenseEvidenceRecord{
		{Relation: "created_token", VerificationStatus: "observed", EvidenceKey: "create-sig:0", Signature: "create-sig", CounterpartKind: "token", CounterpartID: "MintA"},
		{Relation: "direct_sol_transfer_out", VerificationStatus: "verified", CounterpartKind: "wallet", CounterpartID: "Counterparty", EvidenceKey: "sig-one:0", Signature: "sig-one", AmountNative: 1},
		{Relation: "direct_sol_transfer_out", VerificationStatus: "verified", CounterpartKind: "wallet", CounterpartID: "Counterparty", EvidenceKey: "sig-two:0", Signature: "sig-two", AmountNative: 2},
	}
	verdict := EvaluateEvidenceBoundActorDefenseRules(track, evidence)
	if verdict.Grade != "B" || verdict.Verdict != "compounding_rule" || !verdict.Signed {
		t.Fatalf("two distinct rule IDs did not produce B: %#v", verdict)
	}
	if actorRuleDistinctRuleCount(verdict.TriggeredRules) != 2 {
		t.Fatalf("distinct rule IDs=%d want 2", actorRuleDistinctRuleCount(verdict.TriggeredRules))
	}
}

func actorRuleTestHits(items []ActorDefenseRuleHit, ruleID string) []ActorDefenseRuleHit {
	out := []ActorDefenseRuleHit{}
	for _, item := range items {
		if item.RuleID == ruleID {
			out = append(out, item)
		}
	}
	return out
}
