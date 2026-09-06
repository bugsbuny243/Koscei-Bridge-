package services

import (
	"testing"
	"time"
)

func TestClassifyIntelligenceSubjectEVMAddress(t *testing.T) {
	subject := ClassifyIntelligenceSubject("0xe1e5f00a9b0255ca4df85b3130ee0f77d15acc2d", "ethereum-mainnet")
	if subject.ChainFamily != IntelligenceChainFamilyEVM || subject.Chain != "ethereum" || subject.Kind != IntelligenceSubjectAddress {
		t.Fatalf("subject=%#v", subject)
	}
	if subject.ClassificationBasis != "evm_address_syntax" || subject.CanonicalRef == "" || subject.ID == "" {
		t.Fatalf("subject=%#v", subject)
	}
}

func TestClassifyIntelligenceSubjectSolanaAddress(t *testing.T) {
	subject := ClassifyIntelligenceSubject("62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump", "solana-mainnet")
	if subject.ChainFamily != IntelligenceChainFamilySolana || subject.Chain != "solana" || subject.Kind != IntelligenceSubjectAddress {
		t.Fatalf("subject=%#v", subject)
	}
	if subject.ClassificationBasis != "solana_base58_address_syntax" {
		t.Fatalf("subject=%#v", subject)
	}
}

func TestClassifyIntelligenceSubjectUnknownDoesNotPretendSafeOrKnown(t *testing.T) {
	subject := ClassifyIntelligenceSubject("not-a-chain-target", "")
	if subject.ChainFamily != IntelligenceChainFamilyUnknown || subject.Chain != "unknown" || subject.Kind != IntelligenceSubjectUnknown {
		t.Fatalf("subject=%#v", subject)
	}
}

func TestCanonicalRefsDoNotConflateCrossChainSubjects(t *testing.T) {
	target := "0xe1e5f00a9b0255ca4df85b3130ee0f77d15acc2d"
	ethereum := ClassifyIntelligenceSubject(target, "ethereum-mainnet")
	base := ClassifyIntelligenceSubject(target, "base-mainnet")
	if ethereum.CanonicalRef == base.CanonicalRef || ethereum.ID == base.ID {
		t.Fatalf("cross-chain subjects conflated: ethereum=%#v base=%#v", ethereum, base)
	}
}

func TestRelationshipRequiresEvidenceBeforeVerified(t *testing.T) {
	relationship := VerifiedIntelligenceRelationship("source", "target", "funded_by", nil, 0.9)
	if relationship.Status != IntelligenceEvidenceUnverified {
		t.Fatalf("relationship=%#v", relationship)
	}

	relationship = VerifiedIntelligenceRelationship("source", "target", "funded_by", []string{"tx:0xabc"}, 1.4)
	if relationship.Status != IntelligenceEvidenceVerified || relationship.Confidence != 1 {
		t.Fatalf("relationship=%#v", relationship)
	}
}

func TestNewInvestigationStartsUnknownNotSafe(t *testing.T) {
	now := time.Date(2026, 9, 6, 7, 0, 0, 0, time.UTC)
	subject := ClassifyIntelligenceSubject("62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump", "solana-mainnet")
	investigation := BuildIntelligenceInvestigation([]IntelligenceSubject{subject}, now)
	if investigation.ContractVersion != IntelligenceContractVersion {
		t.Fatalf("contract_version=%q", investigation.ContractVersion)
	}
	if investigation.Decision.Status != IntelligenceEvidenceUnverified || investigation.Decision.Action != "investigate" || investigation.Decision.Confidence != 0 {
		t.Fatalf("decision=%#v", investigation.Decision)
	}
	if !investigation.GeneratedAt.Equal(now) {
		t.Fatalf("generated_at=%s", investigation.GeneratedAt)
	}
}
