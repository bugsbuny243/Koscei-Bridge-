package handlers

import (
	"sort"
	"strings"
	"time"
)

const addressBehaviorTimelineSchemaVersion = "koschei-address-behavior-timeline-v1"

type addressBehaviorTimelineEvent struct {
	ObservedAt         time.Time `json:"observed_at"`
	EventType          string    `json:"event_type"`
	Signature          string    `json:"signature,omitempty"`
	Slot               int64     `json:"slot,omitempty"`
	Counterparty       string    `json:"counterparty,omitempty"`
	AssetType          string    `json:"asset_type,omitempty"`
	TokenMint          string    `json:"token_mint,omitempty"`
	AmountNative       float64   `json:"amount_native,omitempty"`
	TokenAmount        float64   `json:"token_amount,omitempty"`
	Program            string    `json:"program,omitempty"`
	VerificationStatus string    `json:"verification_status"`
	Source             string    `json:"source"`
}

type addressBehaviorTimelineCoverage struct {
	DirectFlowComplete   bool   `json:"direct_flow_complete"`
	CreatedMintStatus    string `json:"created_mint_status"`
	CreatedMintVerified  int    `json:"created_mint_verified"`
	CreatedMintRequested int    `json:"created_mint_requested"`
}

type addressBehaviorTimelineReport struct {
	SchemaVersion       string                          `json:"schema_version"`
	Status              string                          `json:"status"`
	Address             string                          `json:"address"`
	EventCount          int                             `json:"event_count"`
	Events              []addressBehaviorTimelineEvent  `json:"events"`
	Coverage            addressBehaviorTimelineCoverage `json:"coverage"`
	EventsSkippedNoTime int                             `json:"events_skipped_no_time"`
	Limitations         []string                        `json:"limitations"`
}

func newAddressBehaviorTimelineReport(wallet string) addressBehaviorTimelineReport {
	return addressBehaviorTimelineReport{
		SchemaVersion: addressBehaviorTimelineSchemaVersion,
		Status:        "no_timestamped_behavior_observed",
		Address:       strings.TrimSpace(wallet),
		Events:        []addressBehaviorTimelineEvent{},
		Limitations:   []string{},
	}
}

// buildAddressBehaviorTimeline is a pure projection over evidence already collected in the request.
// It never performs provider/RPC calls and never invents timestamps for events without chain time.
func buildAddressBehaviorTimeline(wallet string, flow addressFlowReport, created actorCreatedMintIntegrationRun) addressBehaviorTimelineReport {
	out := newAddressBehaviorTimelineReport(wallet)
	out.Coverage = addressBehaviorTimelineCoverage{
		DirectFlowComplete:   flow.FlowComplete,
		CreatedMintStatus:    created.Status,
		CreatedMintVerified:  created.CandidatesVerified,
		CreatedMintRequested: created.CandidatesRequested,
	}

	for _, transfer := range flow.Transfers {
		if transfer.ObservedAt.IsZero() {
			out.EventsSkippedNoTime++
			continue
		}
		eventType := "transfer_out"
		if transfer.Direction == "inbound" {
			eventType = "transfer_in"
		}
		out.Events = append(out.Events, addressBehaviorTimelineEvent{
			ObservedAt:         transfer.ObservedAt.UTC(),
			EventType:          eventType,
			Signature:          strings.TrimSpace(transfer.Signature),
			Slot:               transfer.Slot,
			Counterparty:       strings.TrimSpace(transfer.Counterparty),
			AssetType:          strings.TrimSpace(transfer.AssetType),
			TokenMint:          strings.TrimSpace(transfer.TokenMint),
			AmountNative:       transfer.AmountNative,
			TokenAmount:        transfer.TokenAmount,
			VerificationStatus: strings.TrimSpace(transfer.VerificationStatus),
			Source:             strings.TrimSpace(transfer.Source),
		})
	}

	for _, candidate := range created.VerifiedCandidates {
		observedAt := candidate.ObservedAt
		if observedAt.IsZero() && candidate.BlockTime > 0 {
			observedAt = time.Unix(candidate.BlockTime, 0).UTC()
		}
		if observedAt.IsZero() {
			out.EventsSkippedNoTime++
			continue
		}
		out.Events = append(out.Events, addressBehaviorTimelineEvent{
			ObservedAt:         observedAt.UTC(),
			EventType:          "mint_created",
			Signature:          strings.TrimSpace(candidate.Signature),
			Slot:               candidate.Slot,
			TokenMint:          strings.TrimSpace(candidate.Mint),
			Program:            strings.TrimSpace(candidate.Program),
			VerificationStatus: strings.TrimSpace(candidate.VerificationStatus),
			Source:             strings.TrimSpace(candidate.Source),
		})
	}

	sort.SliceStable(out.Events, func(i, j int) bool {
		if out.Events[i].ObservedAt.Equal(out.Events[j].ObservedAt) {
			if out.Events[i].Slot == out.Events[j].Slot {
				return out.Events[i].Signature < out.Events[j].Signature
			}
			return out.Events[i].Slot < out.Events[j].Slot
		}
		return out.Events[i].ObservedAt.Before(out.Events[j].ObservedAt)
	})

	limit := actorDefenseEnvInt("ARVIS_ADDRESS_BEHAVIOR_TIMELINE_LIMIT", 300, 50, 1000)
	if len(out.Events) > limit {
		out.Events = append([]addressBehaviorTimelineEvent{}, out.Events[len(out.Events)-limit:]...)
		out.Limitations = append(out.Limitations, "Behavior timeline exceeded its bounded output limit; the most recent timestamped evidence was retained.")
	}
	out.EventCount = len(out.Events)
	if out.EventCount > 0 {
		out.Status = "timestamped_behavior_available"
	}
	if !flow.FlowComplete {
		out.Limitations = append(out.Limitations, "Direct-flow history is bounded, so the behavior timeline must not be interpreted as complete wallet history.")
	}
	if created.CandidatesRequested > created.CandidatesVerified || strings.Contains(created.Status, "partial") || strings.Contains(created.Status, "observed") {
		out.Limitations = append(out.Limitations, "Created-mint evidence is not fully verified for every discovered candidate; only verified mint-creation events appear in the timeline.")
	}
	if out.EventsSkippedNoTime > 0 {
		out.Limitations = append(out.Limitations, "Evidence without a trustworthy timestamp was omitted from chronological ordering rather than assigned an inferred time.")
	}
	return out
}
