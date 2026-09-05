package handlers

import (
	"sort"
	"strings"
	"time"
)

const addressRelationshipsSchemaVersion = "koschei-address-relationships-v1"

type addressRelationship struct {
	Address            string    `json:"address"`
	Relation           string    `json:"relation"`
	InboundTransfers   int       `json:"inbound_transfers"`
	OutboundTransfers  int       `json:"outbound_transfers"`
	FirstObservedAt    time.Time `json:"first_observed_at,omitempty"`
	LastObservedAt     time.Time `json:"last_observed_at,omitempty"`
	EvidenceSignatures []string  `json:"evidence_signatures"`
	Assets             []string  `json:"assets"`
	TokenMints         []string  `json:"token_mints"`
	AttributedEntity   string    `json:"attributed_entity,omitempty"`
	AttributedCategory string    `json:"attributed_category,omitempty"`
	AttributionSource  string    `json:"attribution_source,omitempty"`
	Verification       string    `json:"verification"`
	SameActorClaimed   bool      `json:"same_actor_claimed"`
	IdentityClaimed    bool      `json:"identity_claimed"`
}

type addressRelationshipsReport struct {
	SchemaVersion     string                `json:"schema_version"`
	Status            string                `json:"status"`
	Address           string                `json:"address"`
	FlowComplete      bool                  `json:"flow_complete"`
	RelationshipCount int                   `json:"relationship_count"`
	Relationships     []addressRelationship `json:"relationships"`
	Limitations       []string              `json:"limitations"`
	Policy            map[string]any        `json:"policy"`
}

type addressRelationshipBuilder struct {
	row        addressRelationship
	signatures map[string]bool
	assets     map[string]bool
	mints      map[string]bool
}

func buildAddressRelationships(wallet string, flow addressFlowReport, attribution addressAttributionReport) addressRelationshipsReport {
	out := addressRelationshipsReport{
		SchemaVersion: addressRelationshipsSchemaVersion,
		Status:        "no_direct_relationships_observed",
		Address:       strings.TrimSpace(wallet),
		FlowComplete:  flow.FlowComplete,
		Relationships: []addressRelationship{},
		Limitations:   []string{},
		Policy: map[string]any{
			"direct_flow_is_relationship_evidence":      true,
			"same_actor_claim_requires_separate_evidence": true,
			"real_person_identity_claim":                  false,
			"unknown_entity_remains_unknown":              true,
		},
	}

	attributionByAddress := map[string]addressAttributionEntity{}
	for _, entity := range attribution.Entities {
		attributionByAddress[entity.Address] = entity
	}
	builders := map[string]*addressRelationshipBuilder{}
	for _, transfer := range flow.Transfers {
		address := strings.TrimSpace(transfer.Counterparty)
		if address == "" {
			continue
		}
		builder := builders[address]
		if builder == nil {
			builder = &addressRelationshipBuilder{
				row: addressRelationship{
					Address:            address,
					EvidenceSignatures: []string{},
					Assets:             []string{},
					TokenMints:         []string{},
					Verification:       "verified_direct_onchain_flow",
				},
				signatures: map[string]bool{},
				assets:     map[string]bool{},
				mints:      map[string]bool{},
			}
			builders[address] = builder
		}
		if transfer.Direction == "inbound" {
			builder.row.InboundTransfers++
		} else if transfer.Direction == "outbound" {
			builder.row.OutboundTransfers++
		}
		if builder.row.FirstObservedAt.IsZero() || (!transfer.ObservedAt.IsZero() && transfer.ObservedAt.Before(builder.row.FirstObservedAt)) {
			builder.row.FirstObservedAt = transfer.ObservedAt
		}
		if transfer.ObservedAt.After(builder.row.LastObservedAt) {
			builder.row.LastObservedAt = transfer.ObservedAt
		}
		if signature := strings.TrimSpace(transfer.Signature); signature != "" {
			builder.signatures[signature] = true
		}
		if asset := strings.TrimSpace(transfer.AssetType); asset != "" {
			builder.assets[asset] = true
		}
		if mint := strings.TrimSpace(transfer.TokenMint); mint != "" {
			builder.mints[mint] = true
		}
	}

	addresses := make([]string, 0, len(builders))
	for address := range builders {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	for _, address := range addresses {
		builder := builders[address]
		switch {
		case builder.row.InboundTransfers > 0 && builder.row.OutboundTransfers > 0:
			builder.row.Relation = "bidirectional_direct_flow"
		case builder.row.InboundTransfers > 0:
			builder.row.Relation = "inbound_direct_flow"
		default:
			builder.row.Relation = "outbound_direct_flow"
		}
		builder.row.EvidenceSignatures = sortedLimitedKeys(builder.signatures, 8)
		builder.row.Assets = sortedLimitedKeys(builder.assets, 8)
		builder.row.TokenMints = sortedLimitedKeys(builder.mints, 16)
		if entity, ok := attributionByAddress[address]; ok {
			builder.row.AttributedEntity = firstNonEmptyString(entity.Entity, entity.Name)
			builder.row.AttributedCategory = entity.Category
			builder.row.AttributionSource = entity.Source
		}
		out.Relationships = append(out.Relationships, builder.row)
	}
	out.RelationshipCount = len(out.Relationships)
	if out.RelationshipCount > 0 {
		out.Status = "direct_relationships_available"
	}
	if !flow.FlowComplete {
		out.Limitations = append(out.Limitations, "Relationship coverage is bounded because direct fund-flow coverage is incomplete; unseen transactions may contain additional counterparties.")
	}
	return out
}

func sortedLimitedKeys(values map[string]bool, limit int) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
