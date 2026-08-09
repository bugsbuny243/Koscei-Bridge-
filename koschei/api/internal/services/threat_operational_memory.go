package services

import (
	"fmt"
	"strings"
)

const ThreatOperationalMemoryVersion = "koschei-threat-operational-memory-v1"

// AugmentThreatAnticipationWithOperationalMemory adds persistent actor-network
// context to threat anticipation without changing the deterministic grade or
// claiming that operational overlap proves shared identity, intent or future
// malicious action.
func AugmentThreatAnticipationWithOperationalMemory(report ThreatAnticipationReport, memory ActorOperationalMemoryReport) ThreatAnticipationReport {
	if report.EvidencePolicy == nil {
		report.EvidencePolicy = map[string]bool{}
	}
	report.EvidencePolicy["operational_memory_can_change_grade"] = false
	report.EvidencePolicy["operational_overlap_proves_identity"] = false
	report.EvidencePolicy["operational_overlap_predicts_intent"] = false

	if !memory.Available || len(memory.Matches) == 0 {
		return report
	}
	match := memory.Matches[0]
	path := ThreatPathway{
		ID:             "historical_operational_overlap",
		Label:          "Historical operational-network overlap",
		Status:         "watch",
		Capacity:       "unknown",
		EvidenceStatus: normalizeThreatOperationalMemoryStatus(match.EvidenceStatus),
		Summary:        threatOperationalMemorySummary(match),
		EvidenceKeys: []string{
			"actor_operational_memory." + strings.Join(match.Rules, "+"),
		},
		Limitations: []string{
			"Operational overlap does not prove that two wallets are controlled by the same real-world person or entity.",
			"Historical interaction or recurrence does not prove malicious intent or a future exploit/rug event.",
		},
	}
	report.Pathways = append(report.Pathways, path)
	report.Scenarios = append(report.Scenarios, ThreatScenario{
		ID:             "historical_operational_recurrence",
		Title:          "Previously observed operational network reappears",
		Classification: "watch_scenario",
		EvidenceStatus: path.EvidenceStatus,
		Basis:          path.Summary,
		EvidenceKeys:   append([]string{}, path.EvidenceKeys...),
		NextSignals: []string{
			"new verified direct transfer between current creator and matched wallets",
			"repeated creator/funder/recipient relation on the current token",
			"verified liquidity-control or exit activity involving the matched network",
		},
	})
	return report
}

func threatOperationalMemorySummary(match ActorOperationalMatch) string {
	base := fmt.Sprintf("Persistent actor memory matched wallet %s as %s under rules %s.", strings.TrimSpace(match.Wallet), strings.TrimSpace(match.Classification), strings.Join(match.Rules, ","))
	switch match.Classification {
	case "verified_counterparty_link":
		return base + fmt.Sprintf(" %d verified direct relation(s) prove on-chain interaction only; they do not prove shared identity or intent.", match.DirectVerifiedRelations)
	case "repeated_operational_overlap":
		return base + fmt.Sprintf(" %d counterpart(s) and %d relation type(s) recur across the persistent evidence corpus; this is a watch context, not an attribution claim.", match.SharedCounterpartCount, match.SharedRelationCount)
	case "repeated_funding_overlap":
		return base + fmt.Sprintf(" Funding overlap recurs across %d subject token context(s) and %d candidate token context(s); shared funding alone is not identity proof.", match.SubjectTokenContexts, match.CandidateTokenContexts)
	default:
		return base + " The overlap remains contextual and cannot change the deterministic grade by itself."
	}
}

func normalizeThreatOperationalMemoryStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "verified":
		return "verified"
	case "observed":
		return "observed"
	default:
		return "unverified"
	}
}
