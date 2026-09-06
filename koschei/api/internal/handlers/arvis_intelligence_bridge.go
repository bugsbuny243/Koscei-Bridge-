package handlers

import (
	"fmt"
	"strings"
	"time"

	"koschei/api/internal/services"
)

func buildArvisIntelligenceBridge(target, network string, transactions []unifiedTransactionEvidence, now time.Time) services.IntelligenceInvestigation {
	subject := services.ClassifyIntelligenceSubject(target, network)
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{subject}, now)

	if subject.ChainFamily != services.IntelligenceChainFamilySolana {
		return investigation
	}

	for _, tx := range transactions {
		signature := strings.TrimSpace(tx.Signature)
		source := strings.TrimSpace(tx.Source)
		if signature == "" && tx.Slot <= 0 {
			continue
		}
		if source == "" {
			source = "arvis_transaction_evidence"
		}

		observedAt := time.Time{}
		if tx.BlockTime != nil {
			observedAt = tx.BlockTime.UTC()
		}
		id := signature
		if id == "" {
			id = fmt.Sprintf("slot:%d", tx.Slot)
		}

		investigation.Evidence = append(investigation.Evidence, services.IntelligenceEvidence{
			ID:              "arvis_tx:" + id,
			SubjectID:       subject.ID,
			ChainFamily:     subject.ChainFamily,
			Chain:           subject.Chain,
			Network:         subject.Network,
			Source:          source,
			Status:          services.IntelligenceEvidenceObserved,
			TransactionHash: signature,
			BlockOrSlot:     tx.Slot,
			ObservedAt:      observedAt,
			Address:         strings.TrimSpace(tx.Trader),
			Method:          strings.TrimSpace(tx.Direction),
			Provenance:      "existing_arvis_transaction_evidence",
			Confidence:      1,
		})
	}

	return investigation
}

func applyArvisCreatorRelationship(investigation *services.IntelligenceInvestigation, relation actorCreatorRelationRun, network string) {
	if investigation == nil || len(investigation.Subjects) == 0 {
		return
	}
	mintSubject := investigation.Subjects[0]
	if mintSubject.ChainFamily != services.IntelligenceChainFamilySolana {
		return
	}

	creator := strings.TrimSpace(relation.Target.CreatorWallet)
	mint := strings.TrimSpace(relation.Target.Mint)
	evidenceKey := strings.TrimSpace(relation.Evidence.EvidenceKey)
	if creator == "" || mint == "" || !strings.EqualFold(mint, mintSubject.Raw) || evidenceKey == "" {
		return
	}

	creatorSubject := services.ClassifyIntelligenceSubject(creator, network)
	if creatorSubject.ChainFamily != services.IntelligenceChainFamilySolana {
		return
	}
	investigation.Subjects = append(investigation.Subjects, creatorSubject)

	status := services.IntelligenceEvidenceObserved
	verified := strings.EqualFold(strings.TrimSpace(relation.Evidence.VerificationStatus), "verified") &&
		strings.TrimSpace(relation.Evidence.Signature) != "" && relation.Evidence.Slot > 0
	if verified {
		status = services.IntelligenceEvidenceVerified
	}

	evidenceID := "arvis_relation:" + evidenceKey
	investigation.Evidence = append(investigation.Evidence, services.IntelligenceEvidence{
		ID:              evidenceID,
		SubjectID:       creatorSubject.ID,
		ChainFamily:     creatorSubject.ChainFamily,
		Chain:           creatorSubject.Chain,
		Network:         creatorSubject.Network,
		Source:          strings.TrimSpace(relation.Evidence.Source),
		Status:          status,
		TransactionHash: strings.TrimSpace(relation.Evidence.Signature),
		BlockOrSlot:     relation.Evidence.Slot,
		ObservedAt:      relation.Evidence.ObservedAt.UTC(),
		Address:         creator,
		Contract:        mint,
		Method:          "created_token",
		Provenance:      "existing_arvis_canonical_creator_relation",
		Confidence:      1,
		Attributes: map[string]any{
			"verification_status": relation.Evidence.VerificationStatus,
			"evidence_key":        evidenceKey,
		},
	})

	investigation.Entities = append(investigation.Entities, services.IntelligenceEntity{
		ID:           "entity:" + creatorSubject.ID,
		Kind:         "creator_deployer",
		Label:        creator,
		Attribution:  "onchain_role_only",
		Confidence:   1,
		EvidenceRefs: []string{evidenceID},
	})

	relationship := services.VerifiedIntelligenceRelationship(
		creatorSubject.ID,
		mintSubject.ID,
		"created_token",
		[]string{evidenceID},
		1,
	)
	if !verified {
		relationship.Status = services.IntelligenceEvidenceObserved
	}
	investigation.Relationships = append(investigation.Relationships, relationship)
}

func attachArvisIntelligenceBridge(assembly *unifiedInvestigationAssembly) {
	if assembly == nil {
		return
	}
	if assembly.Report == nil {
		assembly.Report = map[string]any{}
	}
	transactions, _ := assembly.Report["transaction_evidence"].([]unifiedTransactionEvidence)
	target := strings.TrimSpace(assembly.Core.Request.Target)
	network := strings.TrimSpace(assembly.Core.Request.Network)
	if network == "" {
		network = "solana-mainnet"
	}
	investigation := buildArvisIntelligenceBridge(target, network, transactions, time.Now().UTC())
	if actorInvestigation, ok := assembly.Report["actor_investigation"].(map[string]any); ok {
		if relation, ok := actorInvestigation["current_creator_relation"].(actorCreatorRelationRun); ok {
			applyArvisCreatorRelationship(&investigation, relation, network)
		}
	}
	assembly.Report["intelligence_contract"] = investigation
}
