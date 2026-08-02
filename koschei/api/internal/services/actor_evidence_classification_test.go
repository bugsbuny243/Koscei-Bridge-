package services

import "testing"

func TestClassifyActorDefenseEvidenceLabelsUnsignedInboundMicroSOL(t *testing.T) {
	item := ActorDefenseEvidenceRecord{
		Relation:     "direct_sol_transfer_in",
		AmountNative: 0.000001,
		Metadata:     map[string]any{"actor_signed": false},
	}
	classification := ClassifyActorDefenseEvidence(item)
	if !classification.PossibleDust || !classification.AddressPoisoningCandidate || classification.GradeEligible {
		t.Fatalf("classification=%#v", classification)
	}
	if len(classification.Labels) != 2 || classification.Labels[0] != "address_poisoning_candidate" || classification.Labels[1] != "possible_dust" {
		t.Fatalf("labels=%#v", classification.Labels)
	}
}

func TestClassifyActorDefenseEvidenceKeepsNormalTransferGradeEligible(t *testing.T) {
	item := ActorDefenseEvidenceRecord{
		Relation:     "direct_sol_transfer_in",
		AmountNative: 0.000010001,
		Metadata:     map[string]any{"actor_signed": false},
	}
	classification := ClassifyActorDefenseEvidence(item)
	if classification.PossibleDust || classification.AddressPoisoningCandidate || !classification.GradeEligible {
		t.Fatalf("classification=%#v", classification)
	}
}

func TestBuildActorDefenseEvidenceLinePublishesDustLabels(t *testing.T) {
	item := ActorDefenseEvidenceRecord{
		ActorWallet:        "ActorWallet",
		CounterpartID:      "DustWallet",
		Relation:           "direct_sol_transfer_in",
		VerificationStatus: "observed",
		Signature:          "sig-dust",
		Slot:               1,
		AmountNative:       0.00001,
		Metadata:           map[string]any{"actor_signed": false},
	}
	line := BuildActorDefenseEvidenceLine(item)
	if !line.PossibleDust || !line.AddressPoisoningCandidate || line.GradeEligible {
		t.Fatalf("line=%#v", line)
	}
	if line.SourceWallet != "DustWallet" || line.DestinationWallet != "ActorWallet" || line.Program != "system" {
		t.Fatalf("evidence endpoints/program=%#v", line)
	}
}
