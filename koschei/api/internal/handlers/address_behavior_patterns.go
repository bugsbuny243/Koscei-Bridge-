package handlers

import (
	"sort"
	"strings"
	"time"
)

const addressBehaviorPatternsSchemaVersion = "koschei-address-behavior-patterns-v1"

type addressBehaviorPatternMatch struct {
	PatternID          string   `json:"pattern_id"`
	Label              string   `json:"label"`
	Triggered          bool     `json:"triggered"`
	Status             string   `json:"status"`
	EvidenceStatus     string   `json:"evidence_status"`
	GradeEligible      bool     `json:"grade_eligible"`
	VerdictAuthority   bool     `json:"verdict_authority"`
	Counterparties     []string `json:"counterparties"`
	TokenMints         []string `json:"token_mints"`
	EvidenceSignatures []string `json:"evidence_signatures"`
	Explanation        string   `json:"explanation"`
	Limitations        []string `json:"limitations"`
}

type addressBehaviorPatternsReport struct {
	SchemaVersion  string                        `json:"schema_version"`
	Status         string                        `json:"status"`
	Address        string                        `json:"address"`
	TriggeredCount int                           `json:"triggered_count"`
	Matches        []addressBehaviorPatternMatch `json:"matches"`
	FlowComplete   bool                          `json:"flow_complete"`
	TimelineEvents int                           `json:"timeline_events"`
	Limitations    []string                      `json:"limitations"`
	Policy         map[string]any                `json:"policy"`
}

func newAddressBehaviorPatternsReport(wallet string) addressBehaviorPatternsReport {
	return addressBehaviorPatternsReport{
		SchemaVersion: addressBehaviorPatternsSchemaVersion,
		Status:        "no_behavior_pattern_observed",
		Address:       strings.TrimSpace(wallet),
		Matches:       []addressBehaviorPatternMatch{},
		Limitations:   []string{},
		Policy: map[string]any{
			"verdict_authority":         false,
			"grade_authority":           false,
			"guard_block_authority":     false,
			"real_world_identity_claim": false,
			"same_operator_claim":       false,
			"wrongdoing_claim":          false,
		},
	}
}

// buildAddressBehaviorPatterns is a zero-RPC projection over evidence already
// collected during the current address investigation. It intentionally does not
// reuse persistent behavioral-signature claims, because those require retained
// multi-incident memory that may be unavailable in stateless production.
func buildAddressBehaviorPatterns(wallet string, flow addressFlowReport, relationships addressRelationshipsReport, timeline addressBehaviorTimelineReport) addressBehaviorPatternsReport {
	out := newAddressBehaviorPatternsReport(wallet)
	out.FlowComplete = flow.FlowComplete
	out.TimelineEvents = timeline.EventCount
	out.Matches = append(out.Matches,
		addressPatternRepeatedCounterparty(relationships),
		addressPatternBidirectionalCounterparty(relationships),
		addressPatternRapidRedistribution(timeline),
		addressPatternRepeatedMintCreation(timeline),
	)
	for _, match := range out.Matches {
		if match.Triggered {
			out.TriggeredCount++
		}
	}
	if out.TriggeredCount > 0 {
		out.Status = "behavior_patterns_observed"
	}
	if !flow.FlowComplete {
		out.Limitations = append(out.Limitations, "Direct-flow coverage is bounded; absence of a request-scoped behavior pattern is not conclusive.")
	}
	if timeline.EventCount == 0 {
		out.Limitations = append(out.Limitations, "No timestamped behavior evidence was available for temporal pattern analysis.")
	}
	out.Limitations = append(out.Limitations,
		"Request-scoped behavior patterns summarize observed on-chain evidence only; they do not identify a real-world person or prove common control across wallets.",
		"These patterns are investigation context only and cannot change a grade, Guard action or signed final verdict.",
	)
	return out
}

func newAddressBehaviorPattern(id, label string) addressBehaviorPatternMatch {
	return addressBehaviorPatternMatch{
		PatternID: id, Label: label, Status: "not_triggered", EvidenceStatus: "not_observed",
		Counterparties: []string{}, TokenMints: []string{}, EvidenceSignatures: []string{}, Limitations: []string{},
	}
}

func addressPatternRepeatedCounterparty(relationships addressRelationshipsReport) addressBehaviorPatternMatch {
	match := newAddressBehaviorPattern("KOSCH-ADDR-BEH-001", "Repeated direct interaction with the same counterparty")
	type candidate struct {
		address    string
		count      int
		signatures []string
	}
	candidates := []candidate{}
	for _, relation := range relationships.Relationships {
		count := relation.InboundTransfers + relation.OutboundTransfers
		if count < 3 || strings.TrimSpace(relation.Address) == "" || len(relation.EvidenceSignatures) < 2 {
			continue
		}
		candidates = append(candidates, candidate{address: relation.Address, count: count, signatures: relation.EvidenceSignatures})
	}
	if len(candidates) == 0 {
		return match
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].count == candidates[j].count {
			return candidates[i].address < candidates[j].address
		}
		return candidates[i].count > candidates[j].count
	})
	for _, item := range candidates {
		match.Counterparties = append(match.Counterparties, item.address)
		match.EvidenceSignatures = append(match.EvidenceSignatures, item.signatures...)
		if len(match.Counterparties) >= 8 {
			break
		}
	}
	match.EvidenceSignatures = uniqueSortedStrings(match.EvidenceSignatures, 16)
	match.Triggered = true
	match.Status = "observed_context"
	match.EvidenceStatus = "verified"
	match.Explanation = "The address has multiple independently decoded direct transfers with one or more of the same counterparties in the observed flow window."
	match.Limitations = append(match.Limitations, "Repeated direct interaction proves address-level recurrence only; it does not establish ownership, collusion or malicious intent.")
	return match
}

func addressPatternBidirectionalCounterparty(relationships addressRelationshipsReport) addressBehaviorPatternMatch {
	match := newAddressBehaviorPattern("KOSCH-ADDR-BEH-002", "Bidirectional direct fund-flow relationship")
	for _, relation := range relationships.Relationships {
		if relation.InboundTransfers == 0 || relation.OutboundTransfers == 0 || strings.TrimSpace(relation.Address) == "" {
			continue
		}
		match.Counterparties = append(match.Counterparties, relation.Address)
		match.EvidenceSignatures = append(match.EvidenceSignatures, relation.EvidenceSignatures...)
	}
	if len(match.Counterparties) == 0 {
		return match
	}
	match.Counterparties = uniqueSortedStrings(match.Counterparties, 12)
	match.EvidenceSignatures = uniqueSortedStrings(match.EvidenceSignatures, 20)
	match.Triggered = true
	match.Status = "observed_context"
	match.EvidenceStatus = "verified"
	match.Explanation = "The observed direct-flow evidence contains both inbound and outbound transfers between the target and the same counterparty address."
	match.Limitations = append(match.Limitations, "Bidirectional flow is an interaction pattern, not proof that the wallets share an operator or purpose.")
	return match
}

func addressPatternRapidRedistribution(timeline addressBehaviorTimelineReport) addressBehaviorPatternMatch {
	match := newAddressBehaviorPattern("KOSCH-ADDR-BEH-003", "Rapid inbound-to-outbound transfer sequence")
	const window = 15 * time.Minute
	for i, event := range timeline.Events {
		if event.EventType != "transfer_in" || event.ObservedAt.IsZero() {
			continue
		}
		for j := i + 1; j < len(timeline.Events); j++ {
			next := timeline.Events[j]
			if next.ObservedAt.IsZero() {
				continue
			}
			delta := next.ObservedAt.Sub(event.ObservedAt)
			if delta > window {
				break
			}
			if delta < 0 || next.EventType != "transfer_out" {
				continue
			}
			if event.Signature != "" {
				match.EvidenceSignatures = append(match.EvidenceSignatures, event.Signature)
			}
			if next.Signature != "" {
				match.EvidenceSignatures = append(match.EvidenceSignatures, next.Signature)
			}
			if event.Counterparty != "" {
				match.Counterparties = append(match.Counterparties, event.Counterparty)
			}
			if next.Counterparty != "" {
				match.Counterparties = append(match.Counterparties, next.Counterparty)
			}
			break
		}
	}
	match.EvidenceSignatures = uniqueSortedStrings(match.EvidenceSignatures, 20)
	match.Counterparties = uniqueSortedStrings(match.Counterparties, 12)
	if len(match.EvidenceSignatures) < 2 {
		return match
	}
	match.Triggered = true
	match.Status = "observed_watch"
	match.EvidenceStatus = "observed"
	match.Explanation = "At least one observed inbound transfer is followed by an outbound transfer within 15 minutes in the request-scoped timeline."
	match.Limitations = append(match.Limitations,
		"Temporal adjacency does not prove that the outgoing asset originated from the preceding inbound transfer; this is a sequencing signal only.",
	)
	return match
}

func addressPatternRepeatedMintCreation(timeline addressBehaviorTimelineReport) addressBehaviorPatternMatch {
	match := newAddressBehaviorPattern("KOSCH-ADDR-BEH-004", "Repeated verified mint creation by the same address")
	for _, event := range timeline.Events {
		if event.EventType != "mint_created" || strings.TrimSpace(event.TokenMint) == "" {
			continue
		}
		match.TokenMints = append(match.TokenMints, event.TokenMint)
		if event.Signature != "" {
			match.EvidenceSignatures = append(match.EvidenceSignatures, event.Signature)
		}
	}
	match.TokenMints = uniqueSortedStrings(match.TokenMints, 20)
	match.EvidenceSignatures = uniqueSortedStrings(match.EvidenceSignatures, 20)
	if len(match.TokenMints) < 2 {
		return match
	}
	match.Triggered = true
	match.Status = "observed_context"
	match.EvidenceStatus = "verified"
	match.Explanation = "The same exact on-chain address has independently verified mint-creation evidence for multiple token mints in the observed investigation evidence."
	match.Limitations = append(match.Limitations, "Creating multiple token mints is not itself evidence of wrongdoing; downstream lifecycle evidence is required for risk conclusions.")
	return match
}

func uniqueSortedStrings(values []string, limit int) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
