package handlers

import (
	"sort"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const creatorOutcomeHistorySchemaVersion = "koschei-creator-outcome-history-v1"

type creatorTokenOutcome struct {
	Mint string `json:"mint"`

	CreationSignature string `json:"creation_signature,omitempty"`

	CreationSlot int64 `json:"creation_slot,omitempty"`

	CreatedOnChainAt *time.Time `json:"created_on_chain_at,omitempty"`

	LastObservedAt time.Time `json:"last_observed_at"`

	CurrentLiquidityUSD float64 `json:"current_liquidity_usd"`

	CurrentPriceUSD float64 `json:"current_price_usd"`

	FateStatus string `json:"fate_status"`

	LifecycleStatus string `json:"lifecycle_status"`

	AgeAvailable bool `json:"age_available"`

	AgeDays float64 `json:"age_days,omitempty"`

	VerifiedLifetimeAvailable bool `json:"verified_lifetime_available"`

	VerifiedLifetimeDays float64 `json:"verified_lifetime_days,omitempty"`

	EvidenceStatus string `json:"evidence_status"`

	RugClaimed bool `json:"rug_claimed"`

	WrongdoingClaimed bool `json:"wrongdoing_claimed"`
}

type creatorOutcomeHistoryReport struct {
	SchemaVersion string `json:"schema_version"`

	Status string `json:"status"`

	CreatorWallet string `json:"creator_wallet"`

	VerifiedTokenCount int `json:"verified_token_count"`

	OutcomeCount int `json:"outcome_count"`

	ActiveCount int `json:"active_count"`

	InactiveOrDeadCount int `json:"inactive_or_dead_count"`

	MarketDataUnavailableCount int `json:"market_data_unavailable_count"`

	VerifiedLifetimeSampleCount int `json:"verified_lifetime_sample_count"`

	Outcomes []creatorTokenOutcome `json:"outcomes"`

	Limitations []string `json:"limitations"`

	Policy map[string]any `json:"policy"`
}

func newCreatorOutcomeHistoryReport(wallet string) creatorOutcomeHistoryReport {
	out := creatorOutcomeHistoryReport{}
	out.SchemaVersion = creatorOutcomeHistorySchemaVersion
	out.Status = "no_verified_creator_outcomes"
	out.CreatorWallet = strings.TrimSpace(wallet)
	out.Outcomes = []creatorTokenOutcome{}
	out.Limitations = []string{}
	out.Policy = map[string]any{}
	out.Policy["verified_creator_mint_evidence_only"] = true
	out.Policy["current_market_snapshot_only"] = true
	out.Policy["inactive_is_not_rug"] = true
	out.Policy["rug_claimed"] = false
	out.Policy["wrongdoing_claimed"] = false
	out.Policy["neon_persistence"] = false
	return out
}

func buildCreatorOutcomeHistory(wallet string, portfolio actorCreatedMintIntegrationRun) creatorOutcomeHistoryReport {
	out := newCreatorOutcomeHistoryReport(wallet)
	out.VerifiedTokenCount = len(portfolio.VerifiedCandidates)
	out.MarketDataUnavailableCount = portfolio.MarketDataUnavailableCandidates

	for _, observation := range portfolio.LifecycleObservations {
		if strings.TrimSpace(observation.Mint) == "" {
			continue
		}
		row := creatorTokenOutcome{}
		row.Mint = strings.TrimSpace(observation.Mint)
		row.CreationSignature = strings.TrimSpace(observation.CreationSignature)
		row.CreationSlot = observation.CreationSlot
		row.CreatedOnChainAt = observation.CreatedOnChainAt
		row.LastObservedAt = observation.LastObservedAt
		row.CurrentLiquidityUSD = observation.CurrentLiquidityUSD
		row.CurrentPriceUSD = observation.CurrentPriceUSD
		row.FateStatus = strings.TrimSpace(observation.FateStatus)
		row.LifecycleStatus = strings.TrimSpace(observation.LifecycleStatus)
		row.AgeAvailable = observation.AgeAvailable
		row.AgeDays = observation.AgeDays
		row.VerifiedLifetimeAvailable = observation.VerifiedLifetimeAvailable
		row.VerifiedLifetimeDays = observation.VerifiedLifetimeDays
		row.EvidenceStatus = "verified_creator_mint_plus_market_snapshot"
		row.RugClaimed = false
		row.WrongdoingClaimed = false
		out.Outcomes = append(out.Outcomes, row)

		switch row.FateStatus {
		case services.ActorTokenFateActive:
			out.ActiveCount++
		case services.ActorTokenFateInactiveOrDead:
			out.InactiveOrDeadCount++
		}
		if row.VerifiedLifetimeAvailable {
			out.VerifiedLifetimeSampleCount++
		}
	}

	sort.SliceStable(out.Outcomes, func(i, j int) bool {
		left := out.Outcomes[i].LastObservedAt
		right := out.Outcomes[j].LastObservedAt
		if left.Equal(right) {
			return out.Outcomes[i].Mint < out.Outcomes[j].Mint
		}
		return left.After(right)
	})
	out.OutcomeCount = len(out.Outcomes)

	switch {
	case out.OutcomeCount > 0 && out.MarketDataUnavailableCount > 0:
		out.Status = "verified_creator_outcomes_available_with_market_gaps"
	case out.OutcomeCount > 0:
		out.Status = "verified_creator_outcomes_available"
	case out.VerifiedTokenCount > 0 && out.MarketDataUnavailableCount > 0:
		out.Status = "verified_creator_tokens_market_outcome_unavailable"
	}
	if out.MarketDataUnavailableCount > 0 {
		out.Limitations = append(out.Limitations, "Some verified creator-linked tokens had no usable market snapshot; missing market data is not treated as inactive or malicious.")
	}
	if out.InactiveOrDeadCount > 0 {
		out.Limitations = append(out.Limitations, "Inactive or zero-liquidity status is a current market observation and does not by itself establish a rug pull, exit scam, common operator, or wrongdoing.")
	}
	if out.VerifiedLifetimeSampleCount == 0 && out.InactiveOrDeadCount > 0 {
		out.Limitations = append(out.Limitations, "No verified liquid-to-inactive transition sample is available in this request-scoped evidence, so token lifetime is not inferred from current age.")
	}
	return out
}
