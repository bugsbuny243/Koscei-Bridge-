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
