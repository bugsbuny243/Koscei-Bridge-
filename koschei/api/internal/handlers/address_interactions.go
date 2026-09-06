package handlers

import (
	"sort"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const addressInteractionsSchemaVersion = "koschei-address-interactions-v1"

type addressInteraction struct {
	Address              string    `json:"address"`
	InteractionKind      string    `json:"interaction_kind"`
	RiskFlag             string    `json:"risk_flag,omitempty"`
	Entity               string    `json:"entity,omitempty"`
	Name                 string    `json:"name,omitempty"`
	Category             string    `json:"category,omitempty"`
	Labels               []string  `json:"labels,omitempty"`
	Tags                 []string  `json:"tags,omitempty"`
	AttributionSource    string    `json:"attribution_source,omitempty"`
	ClassificationSource string    `json:"classification_source,omitempty"`
	MatchedTaxonomy      []string  `json:"matched_taxonomy,omitempty"`
	Verification         string    `json:"verification"`
	InboundTransfers     int       `json:"inbound_transfers"`
	OutboundTransfers    int       `json:"outbound_transfers"`
	SOLIn                float64   `json:"sol_in,omitempty"`
	SOLOut               float64   `json:"sol_out,omitempty"`
	TokenTransfersIn     int       `json:"token_transfers_in"`
	TokenTransfersOut    int       `json:"token_transfers_out"`
	TokenMints           []string  `json:"token_mints"`
	FirstObservedAt      time.Time `json:"first_observed_at,omitempty"`
	LastObservedAt       time.Time `json:"last_observed_at,omitempty"`
	EvidenceSignatures   []string  `json:"evidence_signatures"`
}

type addressInteractionsReport struct {
	SchemaVersion    string               `json:"schema_version"`
	Status           string               `json:"status"`
	Address          string               `json:"address"`
	FlowComplete     bool                 `json:"flow_complete"`
	Counterparties   int                  `json:"counterparties"`
	ClassifiedCount  int                  `json:"classified_count"`
	UnknownCount     int                  `json:"unknown_count"`
	RiskFlaggedCount int                  `json:"risk_flagged_count"`
	KindCounts       map[string]int       `json:"kind_counts"`
	Interactions     []addressInteraction `json:"interactions"`
	Limitations      []string             `json:"limitations"`
	Policy           map[string]any       `json:"policy"`
}

func newAddressInteractionsReport(wallet string) addressInteractionsReport {
	return addressInteractionsReport{
		SchemaVersion: addressInteractionsSchemaVersion,
		Status:        "no_counterparties_observed",
		Address:       strings.TrimSpace(wallet),
		KindCounts:    map[string]int{},
		Interactions:  []addressInteraction{},
		Limitations:   []string{},
		Policy: map[string]any{
			"verified_provider_taxonomy_only":  true,
			"unknown_remains_unknown":           true,
			"transfer_behavior_is_not_identity": true,
			"risk_label_is_provider_metadata":   true,
			"same_actor_claimed":                false,
			"real_world_identity_claim":         false,
			"wrongdoing_claim":                  false,
		},
	}
}

// buildAddressInteractions classifies already-observed counterparties only when
// positive provider attribution exists. It performs no provider/RPC calls and
// does not infer protocol type from transfer behavior.
func buildAddressInteractions(wallet string, flow addressFlowReport, attribution addressAttributionReport) addressInteractionsReport {
	out := newAddressInteractionsReport(wallet)
	out.FlowComplete = flow.FlowComplete
	out.Counterparties = len(flow.Counterparties)
	if len(flow.Counterparties) == 0 {
		if !flow.FlowComplete {
			out.Limitations = append(out.Limitations, "Direct fund-flow coverage is incomplete; unseen transactions may contain additional counterparties.")
		}
		return out
	}

	entityByAddress := make(map[string]addressAttributionEntity, len(attribution.Entities))
	for _, entity := range attribution.Entities {
		entityByAddress[strings.TrimSpace(entity.Address)] = entity
	}
	evidenceByAddress := buildAddressInteractionEvidence(flow.Transfers)
	rows := make([]addressInteraction, 0, len(flow.Counterparties))
	for _, counterparty := range flow.Counterparties {
		address := strings.TrimSpace(counterparty.Address)
		row := addressInteraction{
			Address:            address,
			InteractionKind:    services.WalletEntityKindUnknown,
			Verification:       "verified_direct_onchain_flow_only",
			InboundTransfers:   counterparty.InboundTransfers,
			OutboundTransfers:  counterparty.OutboundTransfers,
			SOLIn:              counterparty.SOLIn,
			SOLOut:             counterparty.SOLOut,
			TokenTransfersIn:   counterparty.TokenTransfersIn,
			TokenTransfersOut:  counterparty.TokenTransfersOut,
			TokenMints:         append([]string{}, counterparty.TokenMints...),
			EvidenceSignatures: []string{},
		}
		if evidence, ok := evidenceByAddress[address]; ok {
			row.FirstObservedAt = evidence.FirstObservedAt
			row.LastObservedAt = evidence.LastObservedAt
			row.EvidenceSignatures = append([]string{}, evidence.Signatures...)
		}
		if entity, ok := entityByAddress[address]; ok && entity.Verification == "provider_verified" {
			label := &services.WalletLabel{
				Address:  entity.Address,
				Name:     entity.Name,
				Entity:   entity.Entity,
				Category: entity.Category,
				Labels:   append([]string{}, entity.Labels...),
				Tags:     append([]string{}, entity.Tags...),
				Source:   entity.Source,
			}
			classification := services.ClassifyWalletLabel(label)
			row.InteractionKind = classification.Kind
			row.RiskFlag = classification.RiskFlag
			row.Entity = entity.Entity
			row.Name = entity.Name
			row.Category = entity.Category
			row.Labels = append([]string{}, entity.Labels...)
			row.Tags = append([]string{}, entity.Tags...)
			row.AttributionSource = entity.Source
			row.ClassificationSource = classification.Source
			row.MatchedTaxonomy = append([]string{}, classification.MatchedTaxonomy...)
			row.Verification = "provider_verified_taxonomy_and_direct_onchain_flow"
		}
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		iCount := rows[i].InboundTransfers + rows[i].OutboundTransfers
		jCount := rows[j].InboundTransfers + rows[j].OutboundTransfers
		if iCount == jCount {
			return rows[i].Address < rows[j].Address
		}
		return iCount > jCount
	})
	out.Interactions = rows
	for _, row := range rows {
		out.KindCounts[row.InteractionKind]++
		if row.InteractionKind == services.WalletEntityKindUnknown {
			out.UnknownCount++
		} else {
			out.ClassifiedCount++
		}
		if row.RiskFlag != "" {
			out.RiskFlaggedCount++
		}
	}

	switch {
	case out.ClassifiedCount > 0 && out.UnknownCount == 0:
		out.Status = "all_observed_counterparties_classified"
	case out.ClassifiedCount > 0:
		out.Status = "verified_interaction_classification_available_with_unknowns"
	default:
		out.Status = "no_verified_interaction_classification"
	}
	if !flow.FlowComplete {
		out.Limitations = append(out.Limitations, "Direct fund-flow coverage is incomplete; unseen transactions may contain additional counterparties or interaction types.")
	}
	if len(attribution.Entities) < len(flow.Counterparties) {
		out.Limitations = append(out.Limitations, "Only positively resolved provider identities can receive an interaction classification; unresolved or attribution-budget-excluded counterparties remain UNKNOWN.")
	}
	out.Limitations = append(out.Limitations, "Provider risk taxonomy is attribution metadata and is not by itself proof of malicious intent, common control, or wrongdoing.")
	return out
}

type addressInteractionEvidence struct {
	FirstObservedAt time.Time
	LastObservedAt  time.Time
	Signatures      []string
}

func buildAddressInteractionEvidence(transfers []addressFlowTransfer) map[string]addressInteractionEvidence {
	out := map[string]addressInteractionEvidence{}
	for _, transfer := range transfers {
		address := strings.TrimSpace(transfer.Counterparty)
		if address == "" {
			continue
		}
		current := out[address]
		if current.FirstObservedAt.IsZero() || (!transfer.ObservedAt.IsZero() && transfer.ObservedAt.Before(current.FirstObservedAt)) {
			current.FirstObservedAt = transfer.ObservedAt
		}
		if current.LastObservedAt.IsZero() || transfer.ObservedAt.After(current.LastObservedAt) {
			current.LastObservedAt = transfer.ObservedAt
		}
		current.Signatures = appendUniqueAddressInteractionSignature(current.Signatures, transfer.Signature, 8)
		out[address] = current
	}
	return out
}

func appendUniqueAddressInteractionSignature(values []string, candidate string, limit int) []string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return values
	}
	for _, value := range values {
		if value == candidate {
			return values
		}
	}
	if limit > 0 && len(values) >= limit {
		return values
	}
	return append(values, candidate)
}
