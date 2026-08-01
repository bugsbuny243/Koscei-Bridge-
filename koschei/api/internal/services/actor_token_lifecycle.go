package services

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	ActorTokenFateActive         = "active"
	ActorTokenFateInactiveOrDead = "inactive_or_dead"
)

// ActorTokenLifecycleInput is one read-only market observation for a verified
// creator-mint relation. It never signs, submits or mutates an on-chain account.
type ActorTokenLifecycleInput struct {
	Network             string
	ActorWallet         string
	Mint                string
	CreationSignature   string
	CreationSlot        int64
	CreatedOnChainAt    time.Time
	ObservedAt          time.Time
	CurrentLiquidityUSD float64
	CurrentPriceUSD     float64
}

// ActorTokenLifecycleObservation preserves the difference between current age
// and a lifecycle transition that Koschei actually observed. A token is called
// dead/inactive from the current zero-liquidity snapshot, but lifetime is marked
// verified only after a positive-liquidity observation is followed by a later
// inactive observation.
type ActorTokenLifecycleObservation struct {
	Network                    string     `json:"network"`
	ActorWallet                string     `json:"actor_wallet"`
	Mint                       string     `json:"mint"`
	CreationSignature          string     `json:"creation_signature,omitempty"`
	CreationSlot               int64      `json:"creation_slot,omitempty"`
	CreatedOnChainAt           *time.Time `json:"created_on_chain_at,omitempty"`
	FirstObservedAt            time.Time  `json:"first_observed_at"`
	LastObservedAt             time.Time  `json:"last_observed_at"`
	FirstLiquidObservedAt      *time.Time `json:"first_liquid_observed_at,omitempty"`
	LastLiquidObservedAt       *time.Time `json:"last_liquid_observed_at,omitempty"`
	FirstInactiveObservedAt    *time.Time `json:"first_inactive_observed_at,omitempty"`
	CurrentInactiveSince       *time.Time `json:"current_inactive_since,omitempty"`
	CurrentLiquidityUSD        float64    `json:"current_liquidity_usd"`
	CurrentPriceUSD            float64    `json:"current_price_usd"`
	FateStatus                 string     `json:"fate_status"`
	ObservationCount           int64      `json:"observation_count"`
	ReactivationCount          int64      `json:"reactivation_count"`
	AgeAvailable               bool       `json:"age_available"`
	AgeDays                    float64    `json:"age_days,omitempty"`
	VerifiedLifetimeAvailable  bool       `json:"verified_lifetime_available"`
	VerifiedLifetimeDays       float64    `json:"verified_lifetime_days,omitempty"`
	VerifiedLiquidLifetimeDays float64    `json:"verified_liquid_lifetime_days,omitempty"`
	LifecycleStatus            string     `json:"lifecycle_status"`
}

// ActorTokenLifecycleSummary is creator-level fate evidence. AverageLifetimeDays
// is emitted only from observed liquid -> inactive transitions; it is never
// substituted with current age.
type ActorTokenLifecycleSummary struct {
	TotalTokens              int     `json:"total_tokens"`
	ActiveTokens             int     `json:"active_tokens"`
	InactiveOrDeadTokens     int     `json:"inactive_or_dead_tokens"`
	AgeSamples               int     `json:"age_samples"`
	AverageObservedAgeDays   float64 `json:"average_observed_age_days,omitempty"`
	AverageActiveAgeDays     float64 `json:"average_active_age_days,omitempty"`
	AverageInactiveAgeDays   float64 `json:"average_inactive_age_days,omitempty"`
	AverageLifetimeAvailable bool    `json:"average_lifetime_available"`
	AverageLifetimeDays      float64 `json:"average_lifetime_days,omitempty"`
	VerifiedLifetimeSamples  int     `json:"verified_lifetime_samples"`
	ReactivatedTokens        int     `json:"reactivated_tokens"`
	LifecycleCoverageStatus  string  `json:"lifecycle_coverage_status"`
	LifetimeDefinition       string  `json:"lifetime_definition"`
}

func BuildActorTokenLifecycleSnapshot(input ActorTokenLifecycleInput) ActorTokenLifecycleObservation {
	input = normalizeActorTokenLifecycleInput(input)
	out := ActorTokenLifecycleObservation{
		Network:             input.Network,
		ActorWallet:         input.ActorWallet,
		Mint:                input.Mint,
		CreationSignature:   input.CreationSignature,
		CreationSlot:        input.CreationSlot,
		FirstObservedAt:     input.ObservedAt,
		LastObservedAt:      input.ObservedAt,
		CurrentLiquidityUSD: input.CurrentLiquidityUSD,
		CurrentPriceUSD:     input.CurrentPriceUSD,
		ObservationCount:    1,
	}
	if !input.CreatedOnChainAt.IsZero() {
		created := input.CreatedOnChainAt.UTC()
		out.CreatedOnChainAt = &created
	}
	if input.CurrentLiquidityUSD > 0 {
		out.FateStatus = ActorTokenFateActive
		observed := input.ObservedAt.UTC()
		out.FirstLiquidObservedAt = &observed
		out.LastLiquidObservedAt = &observed
	} else {
		out.FateStatus = ActorTokenFateInactiveOrDead
		observed := input.ObservedAt.UTC()
		out.FirstInactiveObservedAt = &observed
		out.CurrentInactiveSince = &observed
	}
	return deriveActorTokenLifecycle(out)
}

func (s *ActorDefenseStore) UpsertTokenLifecycleObservation(ctx context.Context, input ActorTokenLifecycleInput) (ActorTokenLifecycleObservation, error) {
	if s == nil || s.DB == nil {
		return ActorTokenLifecycleObservation{}, fmt.Errorf("actor token lifecycle database is unavailable")
	}
	input = normalizeActorTokenLifecycleInput(input)
	if input.ActorWallet == "" || input.Mint == "" {
		return ActorTokenLifecycleObservation{}, fmt.Errorf("actor wallet and mint are required for token lifecycle")
	}

	fate := ActorTokenFateInactiveOrDead
	if input.CurrentLiquidityUSD > 0 {
		fate = ActorTokenFateActive
	}
	var createdAt any
	if !input.CreatedOnChainAt.IsZero() {
		createdAt = input.CreatedOnChainAt.UTC()
	}

	row := s.DB.QueryRowContext(ctx, `
		INSERT INTO security_actor_token_lifecycle (
			network,actor_wallet,mint,creation_signature,creation_slot,created_on_chain_at,
			first_observed_at,last_observed_at,first_liquid_observed_at,last_liquid_observed_at,
			first_inactive_observed_at,current_inactive_since,current_liquidity_usd,current_price_usd,
			fate_status,observation_count,reactivation_count,created_at,updated_at
		) VALUES (
			$1,$2,$3,$4,NULLIF($5,0),$6,$7,$7,
			CASE WHEN $10='active' THEN $7 ELSE NULL END,
			CASE WHEN $10='active' THEN $7 ELSE NULL END,
			CASE WHEN $10='inactive_or_dead' THEN $7 ELSE NULL END,
			CASE WHEN $10='inactive_or_dead' THEN $7 ELSE NULL END,
			$8,$9,$10,1,0,now(),now()
		)
		ON CONFLICT (network,actor_wallet,mint)
		DO UPDATE SET
			creation_signature=COALESCE(NULLIF(EXCLUDED.creation_signature,''),security_actor_token_lifecycle.creation_signature),
			creation_slot=COALESCE(EXCLUDED.creation_slot,security_actor_token_lifecycle.creation_slot),
			created_on_chain_at=CASE
				WHEN security_actor_token_lifecycle.created_on_chain_at IS NULL THEN EXCLUDED.created_on_chain_at
				WHEN EXCLUDED.created_on_chain_at IS NULL THEN security_actor_token_lifecycle.created_on_chain_at
				ELSE LEAST(security_actor_token_lifecycle.created_on_chain_at,EXCLUDED.created_on_chain_at)
			END,
			first_observed_at=LEAST(security_actor_token_lifecycle.first_observed_at,EXCLUDED.first_observed_at),
			last_observed_at=GREATEST(security_actor_token_lifecycle.last_observed_at,EXCLUDED.last_observed_at),
			first_liquid_observed_at=CASE
				WHEN EXCLUDED.fate_status='active' THEN COALESCE(security_actor_token_lifecycle.first_liquid_observed_at,EXCLUDED.last_observed_at)
				ELSE security_actor_token_lifecycle.first_liquid_observed_at
			END,
			last_liquid_observed_at=CASE
				WHEN EXCLUDED.fate_status='active' THEN GREATEST(COALESCE(security_actor_token_lifecycle.last_liquid_observed_at,EXCLUDED.last_observed_at),EXCLUDED.last_observed_at)
				ELSE security_actor_token_lifecycle.last_liquid_observed_at
			END,
			first_inactive_observed_at=CASE
				WHEN EXCLUDED.fate_status='inactive_or_dead' THEN COALESCE(security_actor_token_lifecycle.first_inactive_observed_at,EXCLUDED.last_observed_at)
				ELSE security_actor_token_lifecycle.first_inactive_observed_at
			END,
			current_inactive_since=CASE
				WHEN EXCLUDED.fate_status='active' THEN NULL
				ELSE COALESCE(security_actor_token_lifecycle.current_inactive_since,EXCLUDED.last_observed_at)
			END,
			current_liquidity_usd=EXCLUDED.current_liquidity_usd,
			current_price_usd=EXCLUDED.current_price_usd,
			fate_status=EXCLUDED.fate_status,
			observation_count=security_actor_token_lifecycle.observation_count+1,
			reactivation_count=security_actor_token_lifecycle.reactivation_count+
				CASE WHEN EXCLUDED.fate_status='active' AND security_actor_token_lifecycle.current_inactive_since IS NOT NULL THEN 1 ELSE 0 END,
			updated_at=now()
		RETURNING network,actor_wallet,mint,creation_signature,creation_slot,created_on_chain_at,
			first_observed_at,last_observed_at,first_liquid_observed_at,last_liquid_observed_at,
			first_inactive_observed_at,current_inactive_since,
			current_liquidity_usd::double precision,current_price_usd::double precision,
			fate_status,observation_count,reactivation_count`,
		input.Network, input.ActorWallet, input.Mint, input.CreationSignature, input.CreationSlot,
		createdAt, input.ObservedAt.UTC(), input.CurrentLiquidityUSD, input.CurrentPriceUSD, fate,
	)

	var out ActorTokenLifecycleObservation
	var creationSlot sql.NullInt64
	var created, firstLiquid, lastLiquid, firstInactive, inactiveSince sql.NullTime
	if err := row.Scan(
		&out.Network, &out.ActorWallet, &out.Mint, &out.CreationSignature, &creationSlot, &created,
		&out.FirstObservedAt, &out.LastObservedAt, &firstLiquid, &lastLiquid,
		&firstInactive, &inactiveSince, &out.CurrentLiquidityUSD, &out.CurrentPriceUSD,
		&out.FateStatus, &out.ObservationCount, &out.ReactivationCount,
	); err != nil {
		return ActorTokenLifecycleObservation{}, fmt.Errorf("upsert actor token lifecycle: %w", err)
	}
	if creationSlot.Valid {
		out.CreationSlot = creationSlot.Int64
	}
	out.CreatedOnChainAt = lifecycleTimePointer(created)
	out.FirstLiquidObservedAt = lifecycleTimePointer(firstLiquid)
	out.LastLiquidObservedAt = lifecycleTimePointer(lastLiquid)
	out.FirstInactiveObservedAt = lifecycleTimePointer(firstInactive)
	out.CurrentInactiveSince = lifecycleTimePointer(inactiveSince)
	return deriveActorTokenLifecycle(out), nil
}

func SummarizeActorTokenLifecycles(items []ActorTokenLifecycleObservation) ActorTokenLifecycleSummary {
	out := ActorTokenLifecycleSummary{
		TotalTokens:        len(items),
		LifetimeDefinition: "creation time to the current inactive transition, only when prior positive liquidity was observed",
	}
	var ageTotal, activeAgeTotal, inactiveAgeTotal, lifetimeTotal float64
	activeAgeSamples, inactiveAgeSamples := 0, 0
	for _, item := range items {
		item = deriveActorTokenLifecycle(item)
		switch item.FateStatus {
		case ActorTokenFateActive:
			out.ActiveTokens++
			if item.AgeAvailable {
				activeAgeTotal += item.AgeDays
				activeAgeSamples++
			}
		default:
			out.InactiveOrDeadTokens++
			if item.AgeAvailable {
				inactiveAgeTotal += item.AgeDays
				inactiveAgeSamples++
			}
		}
		if item.AgeAvailable {
			ageTotal += item.AgeDays
			out.AgeSamples++
		}
		if item.VerifiedLifetimeAvailable {
			lifetimeTotal += item.VerifiedLifetimeDays
			out.VerifiedLifetimeSamples++
		}
		if item.ReactivationCount > 0 {
			out.ReactivatedTokens++
		}
	}
	if out.AgeSamples > 0 {
		out.AverageObservedAgeDays = roundLifecycleDays(ageTotal / float64(out.AgeSamples))
	}
	if activeAgeSamples > 0 {
		out.AverageActiveAgeDays = roundLifecycleDays(activeAgeTotal / float64(activeAgeSamples))
	}
	if inactiveAgeSamples > 0 {
		out.AverageInactiveAgeDays = roundLifecycleDays(inactiveAgeTotal / float64(inactiveAgeSamples))
	}
	if out.VerifiedLifetimeSamples > 0 {
		out.AverageLifetimeAvailable = true
		out.AverageLifetimeDays = roundLifecycleDays(lifetimeTotal / float64(out.VerifiedLifetimeSamples))
	}
	switch {
	case out.TotalTokens == 0:
		out.LifecycleCoverageStatus = "no_verified_tokens"
	case out.AgeSamples < out.TotalTokens:
		out.LifecycleCoverageStatus = "partial_creation_time_coverage"
	case out.InactiveOrDeadTokens > 0 && out.VerifiedLifetimeSamples < out.InactiveOrDeadTokens:
		out.LifecycleCoverageStatus = "current_fate_complete_lifetime_transition_partial"
	default:
		out.LifecycleCoverageStatus = "complete_for_observed_transitions"
	}
	return out
}

func normalizeActorTokenLifecycleInput(input ActorTokenLifecycleInput) ActorTokenLifecycleInput {
	input.Network = normalizeRadarNetwork(input.Network)
	input.ActorWallet = strings.TrimSpace(input.ActorWallet)
	input.Mint = strings.TrimSpace(input.Mint)
	input.CreationSignature = strings.TrimSpace(input.CreationSignature)
	if input.ObservedAt.IsZero() {
		input.ObservedAt = time.Now().UTC()
	} else {
		input.ObservedAt = input.ObservedAt.UTC()
	}
	if !input.CreatedOnChainAt.IsZero() {
		input.CreatedOnChainAt = input.CreatedOnChainAt.UTC()
	}
	input.CurrentLiquidityUSD = finiteLifecycleNumber(input.CurrentLiquidityUSD)
	input.CurrentPriceUSD = finiteLifecycleNumber(input.CurrentPriceUSD)
	return input
}

func deriveActorTokenLifecycle(out ActorTokenLifecycleObservation) ActorTokenLifecycleObservation {
	out.AgeAvailable = false
	out.AgeDays = 0
	out.VerifiedLifetimeAvailable = false
	out.VerifiedLifetimeDays = 0
	out.VerifiedLiquidLifetimeDays = 0
	if out.CreatedOnChainAt != nil && !out.LastObservedAt.Before(*out.CreatedOnChainAt) {
		out.AgeAvailable = true
		out.AgeDays = roundLifecycleDays(out.LastObservedAt.Sub(*out.CreatedOnChainAt).Hours() / 24)
	}
	if out.FateStatus == ActorTokenFateActive {
		if out.ReactivationCount > 0 {
			out.LifecycleStatus = "reactivated_after_inactive_observation"
		} else {
			out.LifecycleStatus = "active_age_observed"
		}
		return out
	}
	if out.FirstLiquidObservedAt == nil || out.LastLiquidObservedAt == nil {
		out.LifecycleStatus = "inactive_without_prior_liquid_observation"
		return out
	}
	if out.CurrentInactiveSince == nil || out.CurrentInactiveSince.Before(*out.LastLiquidObservedAt) {
		out.LifecycleStatus = "inactive_transition_unresolved"
		return out
	}
	if out.CreatedOnChainAt == nil || out.CurrentInactiveSince.Before(*out.CreatedOnChainAt) {
		out.LifecycleStatus = "inactive_transition_observed_creation_time_unavailable"
		return out
	}
	out.VerifiedLifetimeAvailable = true
	out.VerifiedLifetimeDays = roundLifecycleDays(out.CurrentInactiveSince.Sub(*out.CreatedOnChainAt).Hours() / 24)
	out.VerifiedLiquidLifetimeDays = roundLifecycleDays(out.CurrentInactiveSince.Sub(*out.FirstLiquidObservedAt).Hours() / 24)
	out.LifecycleStatus = "current_inactive_transition_observed"
	return out
}

func lifecycleTimePointer(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	result := value.Time.UTC()
	return &result
}

func finiteLifecycleNumber(value float64) float64 {
	if value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	return value
}

func roundLifecycleDays(value float64) float64 {
	if value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	return math.Round(value*100) / 100
}
