package handlers

import (
	"context"
	"sort"
	"strings"

	"koschei/api/internal/services"
)

const addressAttributionSchemaVersion = "koschei-address-attribution-v1"

type addressAttributionEntity struct {
	Address       string   `json:"address"`
	Name          string   `json:"name,omitempty"`
	Entity        string   `json:"entity,omitempty"`
	Category      string   `json:"category,omitempty"`
	Labels        []string `json:"labels,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	Source        string   `json:"source"`
	TransferCount int      `json:"transfer_count"`
	InboundCount  int      `json:"inbound_count"`
	OutboundCount int      `json:"outbound_count"`
	Verification  string   `json:"verification"`
	IdentityScope string   `json:"identity_scope"`
}

type addressAttributionReport struct {
	SchemaVersion       string                     `json:"schema_version"`
	Status              string                     `json:"status"`
	Address             string                     `json:"address"`
	TargetResolved      bool                       `json:"target_resolved"`
	TargetEntity        *addressAttributionEntity  `json:"target_entity,omitempty"`
	CounterpartiesSeen  int                        `json:"counterparties_seen"`
	LookupLimit         int                        `json:"lookup_limit"`
	AddressesSelected   int                        `json:"addresses_selected"`
	ResolvedCount       int                        `json:"resolved_count"`
	Entities            []addressAttributionEntity `json:"entities"`
	UnresolvedAddresses []string                   `json:"unresolved_addresses"`
	Limitations         []string                   `json:"limitations"`
	Policy              map[string]any             `json:"policy"`
}

func newAddressAttributionReport(wallet string) addressAttributionReport {
	return addressAttributionReport{
		SchemaVersion:       addressAttributionSchemaVersion,
		Status:              "not_requested",
		Address:             strings.TrimSpace(wallet),
		Entities:            []addressAttributionEntity{},
		UnresolvedAddresses: []string{},
		Limitations:         []string{},
		Policy: map[string]any{
			"verified_provider_attribution_only": true,
			"unknown_remains_unknown":            true,
			"transfer_behavior_is_not_identity":  true,
			"real_person_identity_claim":         false,
			"provider_lookup_is_opt_in":          true,
			"target_address_checked":             true,
		},
	}
}

func collectAddressAttribution(ctx context.Context, wallet, rpcURL string, flow addressFlowReport) addressAttributionReport {
	wallet = strings.TrimSpace(wallet)
	out := newAddressAttributionReport(wallet)
	out.CounterpartiesSeen = len(flow.Counterparties)

	limit := actorDefenseEnvInt("ARVIS_ADDRESS_ATTRIBUTION_LIMIT", 12, 1, 24)
	out.LookupLimit = limit
	selected := selectAddressAttributionCounterparties(flow.Counterparties, limit)
	addresses := make([]string, 0, len(selected)+1)
	counterpartyByAddress := make(map[string]addressFlowCounterparty, len(selected))
	if wallet != "" {
		addresses = append(addresses, wallet)
	}
	for _, counterparty := range selected {
		address := strings.TrimSpace(counterparty.Address)
		if address == "" || address == wallet {
			continue
		}
		addresses = append(addresses, address)
		counterpartyByAddress[address] = counterparty
	}
	out.AddressesSelected = len(addresses)
	if len(addresses) == 0 {
		out.Status = "no_valid_addresses"
		return out
	}

	labels := services.ResolveWalletLabels(ctx, rpcURL, addresses)
	if label := labels[wallet]; label != nil {
		entity := addressAttributionEntityFromLabel(wallet, label, addressFlowCounterparty{})
		out.TargetEntity = &entity
		out.TargetResolved = true
	} else if wallet != "" {
		out.UnresolvedAddresses = append(out.UnresolvedAddresses, wallet)
	}

	for _, counterparty := range selected {
		address := strings.TrimSpace(counterparty.Address)
		if address == "" || address == wallet {
			continue
		}
		label := labels[address]
		if label == nil {
			out.UnresolvedAddresses = append(out.UnresolvedAddresses, address)
			continue
		}
		out.Entities = append(out.Entities, addressAttributionEntityFromLabel(address, label, counterparty))
	}
	out.ResolvedCount = len(out.Entities)
	if out.TargetResolved {
		out.ResolvedCount++
	}
	sort.Slice(out.Entities, func(i, j int) bool {
		if out.Entities[i].TransferCount == out.Entities[j].TransferCount {
			return out.Entities[i].Address < out.Entities[j].Address
		}
		return out.Entities[i].TransferCount > out.Entities[j].TransferCount
	})

	switch {
	case out.TargetResolved && len(out.Entities) > 0:
		out.Status = "target_and_counterparty_attribution_available"
	case out.TargetResolved:
		out.Status = "target_attribution_available"
	case len(out.Entities) > 0:
		out.Status = "verified_counterparty_attribution_available"
	default:
		out.Status = "no_verified_attribution"
		out.Limitations = append(out.Limitations, "No positively verified entity labels were available for the target or selected counterparties. The result does not infer ownership from transfer behavior.")
	}
	if len(flow.Counterparties) > len(selected) {
		out.Limitations = append(out.Limitations, "Counterparty attribution was bounded to the most active addresses to control paid provider usage; the target address is always included when valid.")
	}
	return out
}

func addressAttributionEntityFromLabel(address string, label *services.WalletLabel, counterparty addressFlowCounterparty) addressAttributionEntity {
	return addressAttributionEntity{
		Address:       strings.TrimSpace(address),
		Name:          strings.TrimSpace(label.Name),
		Entity:        strings.TrimSpace(label.Entity),
		Category:      strings.TrimSpace(label.Category),
		Labels:        append([]string{}, label.Labels...),
		Tags:          append([]string{}, label.Tags...),
		Source:        strings.TrimSpace(label.Source),
		TransferCount: counterparty.InboundTransfers + counterparty.OutboundTransfers,
		InboundCount:  counterparty.InboundTransfers,
		OutboundCount: counterparty.OutboundTransfers,
		Verification:  "provider_verified",
		IdentityScope: "known_onchain_entity_not_real_person_identity",
	}
}

func selectAddressAttributionCounterparties(input []addressFlowCounterparty, limit int) []addressFlowCounterparty {
	rows := append([]addressFlowCounterparty{}, input...)
	sort.Slice(rows, func(i, j int) bool {
		iCount := rows[i].InboundTransfers + rows[i].OutboundTransfers
		jCount := rows[j].InboundTransfers + rows[j].OutboundTransfers
		if iCount == jCount {
			return rows[i].Address < rows[j].Address
		}
		return iCount > jCount
	})
	if limit <= 0 || len(rows) <= limit {
		return rows
	}
	return rows[:limit]
}
