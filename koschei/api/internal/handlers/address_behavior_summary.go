package handlers

import (
	"fmt"
	"strings"
)

const addressBehaviorSummarySchemaVersion = "koschei-address-behavior-summary-v1"

type addressBehaviorSummaryReport struct {
	SchemaVersion       string         `json:"schema_version"`
	Status              string         `json:"status"`
	Address             string         `json:"address"`
	EvidenceConfidence  string         `json:"evidence_confidence"`
	PrimaryObservations []string       `json:"primary_observations"`
	EvidenceSignatures  []string       `json:"evidence_signatures"`
	Counterparties      []string       `json:"counterparties"`
	TokenMints          []string       `json:"token_mints"`
	Limitations         []string       `json:"limitations"`
	Policy              map[string]any `json:"policy"`
}

func newAddressBehaviorSummaryReport(wallet string) addressBehaviorSummaryReport {
	return addressBehaviorSummaryReport{
		SchemaVersion:       addressBehaviorSummarySchemaVersion,
		Status:              "insufficient_observed_behavior",
		Address:             strings.TrimSpace(wallet),
		EvidenceConfidence:  "low",
		PrimaryObservations: []string{},
		EvidenceSignatures:  []string{},
		Counterparties:      []string{},
		TokenMints:          []string{},
		Limitations:         []string{},
		Policy: map[string]any{
			"risk_verdict":              false,
			"grade_authority":           false,
			"guard_block_authority":     false,
			"real_world_identity_claim": false,
			"same_operator_claim":       false,
			"wrongdoing_claim":          false,
		},
	}
}

// buildAddressBehaviorSummary turns already-collected address evidence into a
// compact operator-facing narrative. It never performs provider calls and does
// not promote request-scoped observations into a risk verdict.
func buildAddressBehaviorSummary(wallet string, historyComplete bool, flow addressFlowReport, relationships addressRelationshipsReport, timeline addressBehaviorTimelineReport, patterns addressBehaviorPatternsReport) addressBehaviorSummaryReport {
	out := newAddressBehaviorSummaryReport(wallet)
	verifiedMatches := 0
	observedMatches := 0

	for _, match := range patterns.Matches {
		if !match.Triggered {
			continue
		}
		switch match.PatternID {
		case "KOSCH-ADDR-BEH-001":
			out.PrimaryObservations = append(out.PrimaryObservations, fmt.Sprintf("Repeated direct interaction was observed with %d counterparty address(es) in the decoded flow window.", len(match.Counterparties)))
		case "KOSCH-ADDR-BEH-002":
			out.PrimaryObservations = append(out.PrimaryObservations, fmt.Sprintf("Bidirectional direct fund flow was observed with %d counterparty address(es).", len(match.Counterparties)))
		case "KOSCH-ADDR-BEH-003":
			out.PrimaryObservations = append(out.PrimaryObservations, "At least one inbound transfer was followed by an outbound transfer within 15 minutes; this is a sequencing observation, not asset-provenance proof.")
		case "KOSCH-ADDR-BEH-004":
			out.PrimaryObservations = append(out.PrimaryObservations, fmt.Sprintf("The exact address has verified creation evidence for %d distinct token mint(s) in the observed investigation evidence.", len(match.TokenMints)))
		default:
			out.PrimaryObservations = append(out.PrimaryObservations, match.Explanation)
		}
		out.EvidenceSignatures = append(out.EvidenceSignatures, match.EvidenceSignatures...)
		out.Counterparties = append(out.Counterparties, match.Counterparties...)
		out.TokenMints = append(out.TokenMints, match.TokenMints...)
		if match.EvidenceStatus == "verified" {
			verifiedMatches++
		} else if match.EvidenceStatus == "observed" {
			observedMatches++
		}
	}

	out.EvidenceSignatures = uniqueSortedStrings(out.EvidenceSignatures, 24)
	out.Counterparties = uniqueSortedStrings(out.Counterparties, 16)
	out.TokenMints = uniqueSortedStrings(out.TokenMints, 20)

	if len(out.PrimaryObservations) > 0 {
		out.Status = "observed_behavior_summary_available"
	}

	switch {
	case verifiedMatches >= 2 && historyComplete && flow.FlowComplete:
		out.EvidenceConfidence = "high"
	case verifiedMatches >= 1 || (observedMatches >= 1 && timeline.EventCount >= 2):
		out.EvidenceConfidence = "medium"
	default:
		out.EvidenceConfidence = "low"
	}

	if !historyComplete {
		out.Limitations = append(out.Limitations, "Address signature history is bounded; older behavior may exist outside the observed history window.")
	}
	if !flow.FlowComplete {
		out.Limitations = append(out.Limitations, "Direct fund-flow decoding is bounded; the behavior summary does not represent every transaction in the address history.")
	}
	if relationships.RelationshipCount == 0 {
		out.Limitations = append(out.Limitations, "No direct counterparty relationship was resolved from the decoded transfer evidence.")
	}
	out.Limitations = append(out.Limitations,
		"Evidence confidence describes completeness and verification strength of the observed evidence; it is not a probability of malicious behavior.",
		"The summary does not identify a real-world owner, prove common control across addresses, or establish wrongdoing.",
	)
	return out
}
