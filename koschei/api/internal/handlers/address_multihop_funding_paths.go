package handlers

import (
	"context"
	"sort"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const addressMultiHopFundingPathsSchemaVersion = "koschei-address-multihop-funding-paths-v1"

type addressMultiHopFundingExtension struct {
	Direction          string                    `json:"direction"`
	Intermediary       string                    `json:"intermediary"`
	DirectSegment      addressFundingPathSegment `json:"direct_segment"`
	ExtensionSegment   addressFundingPathSegment `json:"extension_segment"`
	EndpointKind       string                    `json:"endpoint_kind"`
	EndpointRiskFlag   string                    `json:"endpoint_risk_flag,omitempty"`
	ElapsedSeconds     int64                     `json:"elapsed_seconds"`
	AssetContinuity    bool                      `json:"asset_continuity"`
	VerificationStatus string                    `json:"verification_status"`
	FundTraceClaimed   bool                      `json:"fund_trace_claimed"`
}

type addressMultiHopFundingPathsReport struct {
	SchemaVersion        string                            `json:"schema_version"`
	Status               string                            `json:"status"`
	Address              string                            `json:"address"`
	ExpansionLimit       int                               `json:"expansion_limit"`
	HistoryLimit         int                               `json:"history_limit"`
	CandidatesSelected   int                               `json:"candidates_selected"`
	CandidatesExpanded   int                               `json:"candidates_expanded"`
	ExtensionsObserved   int                               `json:"extensions_observed"`
	UpstreamExtensions   int                               `json:"upstream_extensions"`
	DownstreamExtensions int                               `json:"downstream_extensions"`
	Extensions           []addressMultiHopFundingExtension `json:"extensions"`
	Limitations          []string                          `json:"limitations"`
	Policy               map[string]any                    `json:"policy"`
}

func newAddressMultiHopFundingPathsReport(wallet string) addressMultiHopFundingPathsReport {
	return addressMultiHopFundingPathsReport{
		SchemaVersion: addressMultiHopFundingPathsSchemaVersion,
		Status:        "no_second_hop_observed",
		Address:       strings.TrimSpace(wallet),
		Extensions:    []addressMultiHopFundingExtension{},
		Limitations:   []string{},
		Policy: map[string]any{
			"bounded_second_hop_only":             true,
			"same_asset_and_time_order_required":  true,
			"fund_trace_claimed":                  false,
			"temporal_sequence_is_not_provenance": true,
			"same_actor_claimed":                  false,
			"real_world_identity_claim":           false,
			"wrongdoing_claim":                    false,
		},
	}
}

// collectAddressMultiHopFundingPaths expands a small, bounded set of direct
// source/destination counterparties by one additional hop. Every emitted edge
// is backed by its own decoded transaction. Matching asset + temporal order is
// required, but the report never claims that fungible units were traced.
func (h *Handler) collectAddressMultiHopFundingPaths(ctx context.Context, wallet, network string, direct addressFundingPathsReport) addressMultiHopFundingPathsReport {
	out := newAddressMultiHopFundingPathsReport(wallet)
	expansionLimit := actorDefenseEnvInt("ARVIS_ADDRESS_MULTIHOP_EXPANSION_LIMIT", 2, 1, 4)
	historyLimit := actorDefenseEnvInt("ARVIS_ADDRESS_MULTIHOP_HISTORY_LIMIT", 15, 5, 40)
	out.ExpansionLimit = expansionLimit
	out.HistoryLimit = historyLimit

	selected := selectMultiHopExpansionSegments(direct, expansionLimit)
	out.CandidatesSelected = len(selected)
	if len(selected) == 0 {
		out.Limitations = append(out.Limitations, "No direct source or downstream segment was available for bounded second-hop expansion.")
		return out
	}

	rpcURL := creatorIntelRPCURL()
	if strings.TrimSpace(rpcURL) == "" {
		out.Status = "rpc_unavailable"
		out.Limitations = append(out.Limitations, "Second-hop funding investigation requires Solana RPC access; this is a collection gap, not evidence that no additional path exists.")
		return out
	}

	for _, directSegment := range selected {
		if ctx.Err() != nil {
			out.Limitations = append(out.Limitations, "Second-hop funding expansion stopped at the request time budget.")
			break
		}
		intermediary := strings.TrimSpace(directSegment.Counterparty)
		if intermediary == "" || intermediary == strings.TrimSpace(wallet) {
			continue
		}

		history, err := services.CollectAddressHistory(ctx, rpcURL, network, intermediary, services.AddressHistoryOptions{
			PageSize: historyLimit,
			MaxPages: 1,
		})
		if err != nil && history.SignaturesSeen == 0 {
			out.Limitations = append(out.Limitations, "A selected intermediary could not be expanded from RPC history; missing second-hop data is not treated as absence of a path.")
			continue
		}
		flow := h.collectAddressFlow(ctx, intermediary, network, history)
		out.CandidatesExpanded++

		extension, direction, ok := compatibleSecondHopTransfer(flow.Transfers, directSegment, wallet)
		if !ok {
			continue
		}

		// Resolve only the observed second-hop endpoint plus intermediary. This
		// keeps paid provider use bounded and leaves unresolved endpoints UNKNOWN.
		attributionFlow := secondHopAttributionFlow(intermediary, network, extension)
		attribution := collectAddressAttribution(ctx, intermediary, rpcURL, attributionFlow)
		entities := addressAttributionEntityMap(attribution)
		extensionSegment := fundingPathSegmentFromTransfer(extension, entities)
		classification := services.WalletEntityClassification{Kind: services.WalletEntityKindUnknown}
		if entity, exists := entities[strings.TrimSpace(extension.Counterparty)]; exists && entity.Verification == "provider_verified" {
			classification = services.ClassifyWalletLabel(&services.WalletLabel{
				Address:  entity.Address,
				Name:     entity.Name,
				Entity:   entity.Entity,
				Category: entity.Category,
				Labels:   append([]string{}, entity.Labels...),
				Tags:     append([]string{}, entity.Tags...),
				Source:   entity.Source,
			})
		}

		elapsed := multiHopElapsedSeconds(extensionSegment, directSegment, direction)
		out.Extensions = append(out.Extensions, addressMultiHopFundingExtension{
			Direction:          direction,
			Intermediary:       intermediary,
			DirectSegment:      directSegment,
			ExtensionSegment:   extensionSegment,
			EndpointKind:       classification.Kind,
			EndpointRiskFlag:   classification.RiskFlag,
			ElapsedSeconds:     elapsed,
			AssetContinuity:    true,
			VerificationStatus: "verified_independent_edges_temporal_sequence",
			FundTraceClaimed:   false,
		})
		if direction == "upstream" {
			out.UpstreamExtensions++
		} else {
			out.DownstreamExtensions++
		}
	}
	out.ExtensionsObserved = len(out.Extensions)

	switch {
	case out.UpstreamExtensions > 0 && out.DownstreamExtensions > 0:
		out.Status = "upstream_and_downstream_second_hops_available"
	case out.UpstreamExtensions > 0:
		out.Status = "upstream_second_hop_available"
	case out.DownstreamExtensions > 0:
		out.Status = "downstream_second_hop_available"
	case out.CandidatesExpanded > 0:
		out.Status = "second_hop_expanded_no_compatible_sequence"
	}
	if out.CandidatesSelected >= expansionLimit {
		out.Limitations = append(out.Limitations, "Second-hop expansion is intentionally bounded to the configured strongest direct counterparties; additional paths may exist outside this window.")
	}
	out.Limitations = append(out.Limitations,
		"Each emitted edge is independently verified, but temporal adjacency does not prove that identical fungible SOL or token units traversed the full path.",
		"A multi-hop path does not prove common control, real-world identity, or wrongdoing.",
	)
	return out
}

func selectMultiHopExpansionSegments(direct addressFundingPathsReport, limit int) []addressFundingPathSegment {
	if limit <= 0 {
		return nil
	}
	inbound := append([]addressFundingPathSegment{}, direct.FundingSources...)
	outbound := append([]addressFundingPathSegment{}, direct.Downstream...)
	sort.SliceStable(inbound, func(i, j int) bool { return inbound[i].ObservedAt.After(inbound[j].ObservedAt) })
	sort.SliceStable(outbound, func(i, j int) bool { return outbound[i].ObservedAt.After(outbound[j].ObservedAt) })

	selected := make([]addressFundingPathSegment, 0, limit)
	seen := map[string]bool{}
	appendOne := func(rows []addressFundingPathSegment) {
		for _, row := range rows {
			address := strings.TrimSpace(row.Counterparty)
			if address == "" || seen[address] || len(selected) >= limit {
				continue
			}
			seen[address] = true
			selected = append(selected, row)
			return
		}
	}
	// Preserve both sides when possible before filling remaining capacity.
	appendOne(inbound)
	appendOne(outbound)
	for _, rows := range [][]addressFundingPathSegment{inbound, outbound} {
		for _, row := range rows {
			if len(selected) >= limit {
				break
			}
			address := strings.TrimSpace(row.Counterparty)
			if address == "" || seen[address] {
				continue
			}
			seen[address] = true
			selected = append(selected, row)
		}
	}
	return selected
}

func compatibleSecondHopTransfer(transfers []addressFlowTransfer, direct addressFundingPathSegment, target string) (addressFlowTransfer, string, bool) {
	rows := append([]addressFlowTransfer{}, transfers...)
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ObservedAt.Before(rows[j].ObservedAt) })

	if direct.Direction == "inbound" {
		for i := len(rows) - 1; i >= 0; i-- {
			candidate := rows[i]
			if candidate.Direction != "inbound" || candidate.ObservedAt.After(direct.ObservedAt) || strings.TrimSpace(candidate.Counterparty) == strings.TrimSpace(target) {
				continue
			}
			if sameFundingPathAsset(fundingPathSegmentFromTransfer(candidate, nil), direct) {
				return candidate, "upstream", true
			}
		}
		return addressFlowTransfer{}, "", false
	}
	if direct.Direction == "outbound" {
		for _, candidate := range rows {
			if candidate.Direction != "outbound" || candidate.ObservedAt.Before(direct.ObservedAt) || strings.TrimSpace(candidate.Counterparty) == strings.TrimSpace(target) {
				continue
			}
			if sameFundingPathAsset(direct, fundingPathSegmentFromTransfer(candidate, nil)) {
				return candidate, "downstream", true
			}
		}
	}
	return addressFlowTransfer{}, "", false
}

func secondHopAttributionFlow(intermediary, network string, transfer addressFlowTransfer) addressFlowReport {
	out := newAddressFlowReport(intermediary, network)
	out.FlowComplete = false
	out.Transfers = []addressFlowTransfer{transfer}
	state := map[string]*addressFlowCounterpartyBuilder{}
	applyAddressFlowCounterparty(state, transfer)
	out.Counterparties = buildAddressFlowCounterparties(state)
	out.CounterpartyCount = len(out.Counterparties)
	return out
}

func addressAttributionEntityMap(report addressAttributionReport) map[string]addressAttributionEntity {
	out := make(map[string]addressAttributionEntity, len(report.Entities)+1)
	if report.TargetEntity != nil {
		out[strings.TrimSpace(report.TargetEntity.Address)] = *report.TargetEntity
	}
	for _, entity := range report.Entities {
		out[strings.TrimSpace(entity.Address)] = entity
	}
	return out
}

func multiHopElapsedSeconds(extension, direct addressFundingPathSegment, direction string) int64 {
	var elapsed time.Duration
	if direction == "upstream" {
		elapsed = direct.ObservedAt.Sub(extension.ObservedAt)
	} else {
		elapsed = extension.ObservedAt.Sub(direct.ObservedAt)
	}
	if elapsed < 0 {
		return 0
	}
	return int64(elapsed / time.Second)
}
