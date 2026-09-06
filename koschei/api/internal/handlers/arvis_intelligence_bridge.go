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
	appendIntelligenceSubjectIfMissing(investigation, creatorSubject)

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

func applyArvisFundingRelationship(investigation *services.IntelligenceInvestigation, origin services.ActorFundingOrigin, network string) {
	if investigation == nil || len(investigation.Subjects) == 0 {
		return
	}
	if investigation.Subjects[0].ChainFamily != services.IntelligenceChainFamilySolana {
		return
	}

	actorEvidence, ok := services.ActorFundingOriginEvidence(origin, network)
	if !ok {
		return
	}
	sourceWallet := strings.TrimSpace(actorEvidence.CounterpartID)
	destinationWallet := strings.TrimSpace(actorEvidence.ActorWallet)
	evidenceKey := strings.TrimSpace(actorEvidence.EvidenceKey)
	if sourceWallet == "" || destinationWallet == "" || evidenceKey == "" {
		return
	}

	sourceSubject := services.ClassifyIntelligenceSubject(sourceWallet, network)
	destinationSubject := services.ClassifyIntelligenceSubject(destinationWallet, network)
	if sourceSubject.ChainFamily != services.IntelligenceChainFamilySolana || destinationSubject.ChainFamily != services.IntelligenceChainFamilySolana {
		return
	}
	appendIntelligenceSubjectIfMissing(investigation, sourceSubject)
	appendIntelligenceSubjectIfMissing(investigation, destinationSubject)

	status := services.IntelligenceEvidenceObserved
	verified := strings.EqualFold(strings.TrimSpace(actorEvidence.VerificationStatus), "verified") &&
		strings.TrimSpace(actorEvidence.Signature) != "" && actorEvidence.Slot > 0
	if verified {
		status = services.IntelligenceEvidenceVerified
	}

	evidenceID := "arvis_funding:" + evidenceKey
	investigation.Evidence = append(investigation.Evidence, services.IntelligenceEvidence{
		ID:              evidenceID,
		SubjectID:       sourceSubject.ID,
		ChainFamily:     sourceSubject.ChainFamily,
		Chain:           sourceSubject.Chain,
		Network:         sourceSubject.Network,
		Source:          strings.TrimSpace(actorEvidence.Source),
		Status:          status,
		TransactionHash: strings.TrimSpace(actorEvidence.Signature),
		BlockOrSlot:     actorEvidence.Slot,
		ObservedAt:      actorEvidence.ObservedAt.UTC(),
		Address:         sourceWallet,
		Method:          strings.TrimSpace(actorEvidence.Relation),
		StateChange:     fmt.Sprintf("funded %s with %.9f SOL", destinationWallet, actorEvidence.AmountNative),
		Provenance:      "existing_arvis_funding_origin_evidence",
		Confidence:      1,
		Attributes: map[string]any{
			"verification_status": actorEvidence.VerificationStatus,
			"evidence_key":        evidenceKey,
			"destination_wallet":  destinationWallet,
			"history_complete":    origin.HistoryComplete,
			"trail_status":        origin.TrailStatus,
		},
	})

	investigation.Entities = append(investigation.Entities, services.IntelligenceEntity{
		ID:           "entity:" + sourceSubject.ID,
		Kind:         "funding_source_wallet",
		Label:        sourceWallet,
		Attribution:  "onchain_role_only",
		Confidence:   1,
		EvidenceRefs: []string{evidenceID},
	})

	relationship := services.VerifiedIntelligenceRelationship(
		sourceSubject.ID,
		destinationSubject.ID,
		strings.TrimSpace(actorEvidence.Relation),
		[]string{evidenceID},
		1,
	)
	if !verified {
		relationship.Status = services.IntelligenceEvidenceObserved
	}
	investigation.Relationships = append(investigation.Relationships, relationship)
}

func appendIntelligenceSubjectIfMissing(investigation *services.IntelligenceInvestigation, subject services.IntelligenceSubject) {
	if investigation == nil || strings.TrimSpace(subject.ID) == "" {
		return
	}
	for _, existing := range investigation.Subjects {
		if existing.ID == subject.ID {
			return
		}
	}
	investigation.Subjects = append(investigation.Subjects, subject)
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
		if origin, ok := actorInvestigation["funding_origin"].(services.ActorFundingOrigin); ok {
			applyArvisFundingRelationship(&investigation, origin, network)
		}
	}
	if behavior, ok := assembly.Report["behavior_signals"].(services.UnifiedRadarBehaviorReport); ok {
		applyArvisBehaviorFindings(&investigation, behavior)
	}
	assembly.Report["intelligence_contract"] = investigation
}
