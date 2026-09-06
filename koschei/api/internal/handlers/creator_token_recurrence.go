package handlers

import (
	"sort"
	"strings"
)

const creatorTokenRecurrenceSchemaVersion = "koschei-creator-token-recurrence-v1"

type creatorTokenRecurrenceEvidence struct {
	Mint string `json:"mint"`

	Counterparty string `json:"counterparty"`

	CounterpartyKind string `json:"counterparty_kind"`

	Signature string `json:"signature"`

	Slot int64 `json:"slot"`

	LifecycleFate string `json:"lifecycle_fate,omitempty"`
}

type creatorTokenRecurrencePattern struct {
	PatternType string `json:"pattern_type"`

	PatternValue string `json:"pattern_value"`

	DistinctMintCount int `json:"distinct_mint_count"`

	EvidenceCount int `json:"evidence_count"`

	Evidence []creatorTokenRecurrenceEvidence `json:"evidence"`

	VerificationStatus string `json:"verification_status"`

	MaliciousnessClaimed bool `json:"maliciousness_claimed"`
}

type creatorTokenRecurrenceReport struct {
	SchemaVersion string `json:"schema_version"`

	Status string `json:"status"`

	CreatorWallet string `json:"creator_wallet"`

	DistinctMintsWithPaths int `json:"distinct_mints_with_paths"`

	RecurringPatternCount int `json:"recurring_pattern_count"`

	RecurringCounterpartyCount int `json:"recurring_counterparty_count"`

	RecurringEndpointKindCount int `json:"recurring_endpoint_kind_count"`

	Patterns []creatorTokenRecurrencePattern `json:"patterns"`

	Limitations []string `json:"limitations"`

	Policy map[string]any `json:"policy"`
}

func newCreatorTokenRecurrenceReport(wallet string) creatorTokenRecurrenceReport {
	out := creatorTokenRecurrenceReport{}
	out.SchemaVersion = creatorTokenRecurrenceSchemaVersion
	out.Status = "no_cross_token_recurrence_observed"
	out.CreatorWallet = strings.TrimSpace(wallet)
	out.Patterns = []creatorTokenRecurrencePattern{}
	out.Limitations = []string{}
	out.Policy = map[string]any{}
	out.Policy["minimum_distinct_mints_for_recurrence"] = 2
	out.Policy["verified_observed_paths_only"] = true
	out.Policy["recurrence_is_not_maliciousness"] = true
	out.Policy["same_actor_beyond_creator_wallet_not_claimed"] = true
	out.Policy["wrongdoing_claimed"] = false
	out.Policy["numeric_probability_disabled"] = true
	out.Policy["neon_persistence"] = false
	return out
}

// buildCreatorTokenRecurrence identifies repeated movement characteristics
// across at least two distinct verified creator-linked token mints. It does not
// add collection work and does not infer intent, causation, or wrongdoing.
func buildCreatorTokenRecurrence(wallet string, observed creatorTokenObservedPathsReport) creatorTokenRecurrenceReport {
	out := newCreatorTokenRecurrenceReport(wallet)
	mintSet := map[string]bool{}
	for _, path := range observed.Paths {
		mint := strings.TrimSpace(path.Mint)
		if mint != "" {
			mintSet[mint] = true
		}
	}
	out.DistinctMintsWithPaths = len(mintSet)
	if len(mintSet) < 2 {
		out.Limitations = append(out.Limitations, "Cross-token recurrence requires verified movement paths for at least two distinct creator-linked mints.")
		return out
	}

	byCounterparty := map[string][]creatorTokenObservedPath{}
	byKind := map[string][]creatorTokenObservedPath{}
	for _, path := range observed.Paths {
		mint := strings.TrimSpace(path.Mint)
		if mint == "" || strings.TrimSpace(path.Signature) == "" || path.Slot <= 0 {
			continue
		}
		counterparty := strings.TrimSpace(path.Counterparty)
		if counterparty != "" {
			byCounterparty[counterparty] = append(byCounterparty[counterparty], path)
		}
		kind := strings.TrimSpace(path.CounterpartyKind)
		if kind != "" && kind != "unknown" {
			byKind[kind] = append(byKind[kind], path)
		}
	}

	counterparties := sortedRecurrenceKeys(byCounterparty)
	for _, counterparty := range counterparties {
		pattern, ok := recurrencePatternFromPaths("counterparty", counterparty, byCounterparty[counterparty])
		if !ok {
			continue
		}
		out.Patterns = append(out.Patterns, pattern)
		out.RecurringCounterpartyCount++
	}

	kinds := sortedRecurrenceKeys(byKind)
	for _, kind := range kinds {
		pattern, ok := recurrencePatternFromPaths("endpoint_kind", kind, byKind[kind])
		if !ok {
			continue
		}
		out.Patterns = append(out.Patterns, pattern)
		out.RecurringEndpointKindCount++
	}

	out.RecurringPatternCount = len(out.Patterns)
	if out.RecurringPatternCount > 0 {
		out.Status = "verified_cross_token_movement_recurrence_observed"
	}
	if !observed.PolicyBool("verified_direct_transfer_only") {
		out.Limitations = append(out.Limitations, "Observed-path verification policy was unavailable; recurrence does not upgrade underlying evidence quality.")
	}
	out.Limitations = append(out.Limitations, "Repeated counterparties or endpoint categories across creator-linked tokens describe observed movement recurrence only; they do not establish coordinated abuse, a sale, a rug pull, or wrongdoing.")
	return out
}

func recurrencePatternFromPaths(patternType, patternValue string, paths []creatorTokenObservedPath) (creatorTokenRecurrencePattern, bool) {
	mintSet := map[string]bool{}
	evidence := make([]creatorTokenRecurrenceEvidence, 0, len(paths))
	seenEvidence := map[string]bool{}
	for _, path := range paths {
		mint := strings.TrimSpace(path.Mint)
		signature := strings.TrimSpace(path.Signature)
		if mint == "" || signature == "" || path.Slot <= 0 {
			continue
		}
		mintSet[mint] = true
		key := mint + "\x00" + signature + "\x00" + strings.TrimSpace(path.Counterparty)
		if seenEvidence[key] {
			continue
		}
		seenEvidence[key] = true
		evidence = append(evidence, creatorTokenRecurrenceEvidence{
			Mint:             mint,
			Counterparty:     strings.TrimSpace(path.Counterparty),
			CounterpartyKind: strings.TrimSpace(path.CounterpartyKind),
			Signature:        signature,
			Slot:             path.Slot,
			LifecycleFate:    strings.TrimSpace(path.LifecycleFate),
		})
	}
	if len(mintSet) < 2 {
		return creatorTokenRecurrencePattern{}, false
	}
	sort.SliceStable(evidence, func(i, j int) bool {
		if evidence[i].Mint == evidence[j].Mint {
			if evidence[i].Slot == evidence[j].Slot {
				return evidence[i].Signature < evidence[j].Signature
			}
			return evidence[i].Slot < evidence[j].Slot
		}
		return evidence[i].Mint < evidence[j].Mint
	})
	return creatorTokenRecurrencePattern{
		PatternType:          patternType,
		PatternValue:         patternValue,
		DistinctMintCount:    len(mintSet),
		EvidenceCount:        len(evidence),
		Evidence:             evidence,
		VerificationStatus:   "verified_cross_token_recurrence_from_observed_paths",
		MaliciousnessClaimed: false,
	}, true
}

func sortedRecurrenceKeys[T any](input map[string][]T) []string {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (report creatorTokenObservedPathsReport) PolicyBool(key string) bool {
	value, ok := report.Policy[key].(bool)
	return ok && value
}
