package handlers

import (
	"sort"
	"strings"
	"time"
)

const addressFundingPathsSchemaVersion = "koschei-address-funding-paths-v1"

type addressFundingPathEndpoint struct {
	Address           string   `json:"address"`
	Name              string   `json:"name,omitempty"`
	Entity            string   `json:"entity,omitempty"`
	Category          string   `json:"category,omitempty"`
	AttributionSource string   `json:"attribution_source,omitempty"`
	Labels            []string `json:"labels,omitempty"`
	Verification      string   `json:"verification,omitempty"`
}

type addressFundingPathSegment struct {
	Direction          string                      `json:"direction"`
	Counterparty       string                      `json:"counterparty"`
	Signature          string                      `json:"signature"`
	Slot               int64                       `json:"slot"`
	ObservedAt         time.Time                   `json:"observed_at"`
	AssetType          string                      `json:"asset_type"`
	TokenMint          string                      `json:"token_mint,omitempty"`
	AmountNative       float64                     `json:"amount_native,omitempty"`
	TokenAmount        float64                     `json:"token_amount,omitempty"`
	VerificationStatus string                      `json:"verification_status"`
	Source             string                      `json:"source"`
	Endpoint           *addressFundingPathEndpoint `json:"endpoint,omitempty"`
}

type addressFundingPathCandidate struct {
	SourceSegment      addressFundingPathSegment `json:"source_segment"`
	DownstreamSegment  addressFundingPathSegment `json:"downstream_segment"`
	ElapsedSeconds     int64                     `json:"elapsed_seconds"`
	AssetContinuity    bool                      `json:"asset_continuity"`
	VerificationStatus string                    `json:"verification_status"`
	FundTraceClaimed   bool                      `json:"fund_trace_claimed"`
}

type addressFundingPathsReport struct {
	SchemaVersion      string                        `json:"schema_version"`
	Status             string                        `json:"status"`
	Address            string                        `json:"address"`
	FlowComplete       bool                          `json:"flow_complete"`
	FundingSourceCount int                           `json:"funding_source_count"`
	DownstreamCount    int                           `json:"downstream_count"`
	PathCandidateCount int                           `json:"path_candidate_count"`
	FundingSources     []addressFundingPathSegment   `json:"funding_sources"`
	Downstream         []addressFundingPathSegment   `json:"downstream"`
	PathCandidates     []addressFundingPathCandidate `json:"path_candidates"`
	Limitations        []string                      `json:"limitations"`
	Policy             map[string]any                `json:"policy"`
}

func newAddressFundingPathsReport(wallet string) addressFundingPathsReport {
	return addressFundingPathsReport{
		SchemaVersion:  addressFundingPathsSchemaVersion,
		Status:         "no_direct_funding_path_observed",
		Address:        strings.TrimSpace(wallet),
		FundingSources: []addressFundingPathSegment{},
		Downstream:     []addressFundingPathSegment{},
		PathCandidates: []addressFundingPathCandidate{},
		Limitations:    []string{},
		Policy: map[string]any{
			"direct_transfer_evidence_only":       true,
			"fund_trace_claimed":                  false,
			"same_actor_claimed":                  false,
			"real_world_identity_claim":           false,
			"wrongdoing_claim":                    false,
			"temporal_sequence_is_not_provenance": true,
		},
	}
}

// buildAddressFundingPaths projects already-decoded direct transfer evidence
// into bounded source -> target -> downstream temporal sequences. It performs
// no RPC/provider calls and deliberately does not claim fungible-asset tracing.
func buildAddressFundingPaths(wallet string, flow addressFlowReport, attribution addressAttributionReport) addressFundingPathsReport {
	out := newAddressFundingPathsReport(wallet)
	out.FlowComplete = flow.FlowComplete
	entityByAddress := make(map[string]addressAttributionEntity, len(attribution.Entities)+1)
	if attribution.TargetEntity != nil {
		entityByAddress[strings.TrimSpace(attribution.TargetEntity.Address)] = *attribution.TargetEntity
	}
	for _, entity := range attribution.Entities {
		entityByAddress[strings.TrimSpace(entity.Address)] = entity
	}

	transfers := append([]addressFlowTransfer{}, flow.Transfers...)
	sort.SliceStable(transfers, func(i, j int) bool {
		if transfers[i].ObservedAt.Equal(transfers[j].ObservedAt) {
			if transfers[i].Slot == transfers[j].Slot {
				return transfers[i].Signature < transfers[j].Signature
			}
			return transfers[i].Slot < transfers[j].Slot
		}
		return transfers[i].ObservedAt.Before(transfers[j].ObservedAt)
	})

	inbound := make([]addressFundingPathSegment, 0)
	outbound := make([]addressFundingPathSegment, 0)
	for _, transfer := range transfers {
		segment := fundingPathSegmentFromTransfer(transfer, entityByAddress)
		switch transfer.Direction {
		case "inbound":
			inbound = append(inbound, segment)
		case "outbound":
			outbound = append(outbound, segment)
		}
	}
	out.FundingSources = inbound
	out.Downstream = outbound
	out.FundingSourceCount = len(inbound)
	out.DownstreamCount = len(outbound)

	pathLimit := actorDefenseEnvInt("ARVIS_ADDRESS_FUNDING_PATH_LIMIT", 80, 10, 250)
	for _, downstream := range outbound {
		if len(out.PathCandidates) >= pathLimit {
			break
		}
		source, ok := mostRecentCompatibleFundingSource(inbound, downstream)
		if !ok {
			continue
		}
		elapsed := downstream.ObservedAt.Sub(source.ObservedAt)
		if elapsed < 0 {
			continue
		}
		out.PathCandidates = append(out.PathCandidates, addressFundingPathCandidate{
			SourceSegment:      source,
			DownstreamSegment:  downstream,
			ElapsedSeconds:     int64(elapsed / time.Second),
			AssetContinuity:    true,
			VerificationStatus: "verified_direct_segments_temporal_sequence",
			FundTraceClaimed:   false,
		})
	}
	out.PathCandidateCount = len(out.PathCandidates)

	switch {
	case out.PathCandidateCount > 0:
		out.Status = "observed_source_to_downstream_sequences_available"
	case out.FundingSourceCount > 0 && out.DownstreamCount > 0:
		out.Status = "direct_sources_and_downstream_observed_without_compatible_sequence"
	case out.FundingSourceCount > 0:
		out.Status = "direct_funding_sources_observed"
	case out.DownstreamCount > 0:
		out.Status = "direct_downstream_observed"
	}

	if !flow.FlowComplete {
		out.Limitations = append(out.Limitations, "Direct fund-flow coverage is bounded; unseen transactions may contain earlier funding sources or additional downstream destinations.")
	}
	if len(out.PathCandidates) >= pathLimit && pathLimit > 0 {
		out.Limitations = append(out.Limitations, "Funding-path output reached its bounded candidate limit; additional compatible temporal sequences may exist in the decoded evidence.")
	}
	out.Limitations = append(out.Limitations,
		"A source-to-target transfer followed by a target-to-destination transfer is a verified temporal sequence, not proof that the same fungible SOL or token units were forwarded.",
		"Direct transfer relationships do not prove common control, real-world identity, or wrongdoing.",
	)
	return out
}

func fundingPathSegmentFromTransfer(transfer addressFlowTransfer, entities map[string]addressAttributionEntity) addressFundingPathSegment {
	segment := addressFundingPathSegment{
		Direction:          transfer.Direction,
		Counterparty:       strings.TrimSpace(transfer.Counterparty),
		Signature:          strings.TrimSpace(transfer.Signature),
		Slot:               transfer.Slot,
		ObservedAt:         transfer.ObservedAt,
		AssetType:          strings.TrimSpace(transfer.AssetType),
		TokenMint:          strings.TrimSpace(transfer.TokenMint),
		AmountNative:       transfer.AmountNative,
		TokenAmount:        transfer.TokenAmount,
		VerificationStatus: strings.TrimSpace(transfer.VerificationStatus),
		Source:             strings.TrimSpace(transfer.Source),
	}
	if entity, ok := entities[segment.Counterparty]; ok {
		segment.Endpoint = &addressFundingPathEndpoint{
			Address:           entity.Address,
			Name:              entity.Name,
			Entity:            entity.Entity,
			Category:          entity.Category,
			AttributionSource: entity.Source,
			Labels:            append([]string{}, entity.Labels...),
			Verification:      entity.Verification,
		}
	}
	return segment
}

func mostRecentCompatibleFundingSource(inbound []addressFundingPathSegment, downstream addressFundingPathSegment) (addressFundingPathSegment, bool) {
	for i := len(inbound) - 1; i >= 0; i-- {
		source := inbound[i]
		if source.ObservedAt.After(downstream.ObservedAt) {
			continue
		}
		if !sameFundingPathAsset(source, downstream) {
			continue
		}
		return source, true
	}
	return addressFundingPathSegment{}, false
}

func sameFundingPathAsset(left, right addressFundingPathSegment) bool {
	if left.AssetType != right.AssetType || left.AssetType == "" {
		return false
	}
	if left.AssetType == "SPL_TOKEN" {
		return left.TokenMint != "" && left.TokenMint == right.TokenMint
	}
	return left.AssetType == "SOL"
}
