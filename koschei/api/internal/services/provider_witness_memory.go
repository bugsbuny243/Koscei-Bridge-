package services

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"koschei/api/internal/web3"
)

const ProviderWitnessMemoryRuleset = "koschei-provider-witness-memory-v1"

type ProviderWitnessMemory struct {
	Network             string    `json:"network"`
	Method              string    `json:"method"`
	Provider            string    `json:"provider"`
	Observations        int64     `json:"observations"`
	QuorumAgreements    int64     `json:"quorum_agreements"`
	QuorumDisagreements int64     `json:"quorum_disagreements"`
	ConflictObservations int64    `json:"conflict_observations"`
	UnavailableCount    int64     `json:"unavailable_count"`
	MalformedCount      int64     `json:"malformed_count"`
	RateLimitedCount    int64     `json:"rate_limited_count"`
	LastWitnessStatus   string    `json:"last_witness_status"`
	LastErrorClass      string    `json:"last_error_class,omitempty"`
	LastValueHash       string    `json:"last_value_hash,omitempty"`
	LastContextSlot     int64     `json:"last_context_slot"`
	TrustState          string    `json:"trust_state"`
	FirstObservedAt     time.Time `json:"first_observed_at"`
	LastObservedAt      time.Time `json:"last_observed_at"`
}

type ProviderWitnessMemoryReport struct {
	Available   bool                    `json:"available"`
	Network     string                  `json:"network"`
	Status      string                  `json:"status"`
	ProviderCount int                   `json:"provider_count"`
	Providers   []ProviderWitnessMemory `json:"providers"`
	GeneratedAt time.Time               `json:"generated_at"`
	Policy      map[string]any          `json:"policy"`
}

type providerWitnessObservation struct {
	Agreement    bool
	Disagreement bool
	Conflict     bool
	Unavailable  bool
	Malformed    bool
	RateLimited  bool
}

func classifyProviderWitnessObservation(court web3.EvidenceCourtResult, witness web3.EvidenceCourtWitness) providerWitnessObservation {
	out := providerWitnessObservation{}
	witnessStatus := strings.ToLower(strings.TrimSpace(witness.Status))
	errorClass := strings.ToLower(strings.TrimSpace(witness.ErrorClass))
	courtStatus := strings.ToLower(strings.TrimSpace(court.Status))

	switch witnessStatus {
	case "malformed":
		out.Malformed = true
	case "unavailable", "not_queried":
		out.Unavailable = true
	}
	if errorClass == "rate_limited" {
		out.RateLimited = true
		out.Unavailable = true
	}

	if witnessStatus != "observed" {
		return out
	}
	if courtStatus == "conflict" {
		out.Conflict = true
		return out
	}
	if courtStatus != "verified" || strings.TrimSpace(court.ValueHash) == "" {
		return out
	}
	if strings.EqualFold(strings.TrimSpace(witness.ValueHash), strings.TrimSpace(court.ValueHash)) {
		out.Agreement = true
	} else if strings.TrimSpace(witness.ValueHash) != "" {
		out.Disagreement = true
	}
	return out
}

func deriveProviderWitnessTrustState(memory ProviderWitnessMemory) string {
	// Quarantine is only a candidate state. It never removes a provider from
	// Evidence Court by itself; enforcement must remain an explicit policy step.
	if memory.QuorumDisagreements >= 5 || (memory.QuorumDisagreements >= 3 && memory.MalformedCount >= 1) {
		return "quarantine_candidate"
	}
	if memory.QuorumDisagreements >= 2 {
		return "divergent"
	}
	if memory.QuorumDisagreements == 0 && (memory.UnavailableCount >= 3 || memory.RateLimitedCount >= 3) {
		return "availability_degraded"
	}
	if memory.Observations >= 3 && memory.QuorumAgreements >= 3 && memory.QuorumDisagreements == 0 && memory.MalformedCount == 0 {
		return "consistent"
	}
	return "learning"
}

// RecordEvidenceCourtWitnessMemory persists historical witness behavior without
// changing the Court result. A verified quorum may identify agreement or
// disagreement. A full Court conflict cannot identify which witness is wrong,
// so observed witnesses receive only a neutral conflict observation.
func RecordEvidenceCourtWitnessMemory(ctx context.Context, db *sql.DB, network string, court web3.EvidenceCourtResult) error {
	if db == nil || !court.Enabled || len(court.Witnesses) == 0 {
		return nil
	}
	network = normalizeRadarNetwork(network)
	method := strings.TrimSpace(court.Method)
	if method == "" {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, witness := range court.Witnesses {
		provider := normalizeProviderWitnessLabel(witness.Provider)
		if provider == "" || provider == "context" || provider == "unknown" {
			continue
		}
		observation := classifyProviderWitnessObservation(court, witness)
		lastSlot := int64(witness.ContextSlot)
		var memory ProviderWitnessMemory
		err := tx.QueryRowContext(ctx, `
			INSERT INTO security_provider_witness_memory (
				network,method,provider,observations,quorum_agreements,quorum_disagreements,
				conflict_observations,unavailable_count,malformed_count,rate_limited_count,
				last_witness_status,last_error_class,last_value_hash,last_context_slot,
				trust_state,first_observed_at,last_observed_at,updated_at
			) VALUES (
				$1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'learning',now(),now(),now()
			)
			ON CONFLICT (network,method,provider) DO UPDATE SET
				observations=security_provider_witness_memory.observations+1,
				quorum_agreements=security_provider_witness_memory.quorum_agreements+EXCLUDED.quorum_agreements,
				quorum_disagreements=security_provider_witness_memory.quorum_disagreements+EXCLUDED.quorum_disagreements,
				conflict_observations=security_provider_witness_memory.conflict_observations+EXCLUDED.conflict_observations,
				unavailable_count=security_provider_witness_memory.unavailable_count+EXCLUDED.unavailable_count,
				malformed_count=security_provider_witness_memory.malformed_count+EXCLUDED.malformed_count,
				rate_limited_count=security_provider_witness_memory.rate_limited_count+EXCLUDED.rate_limited_count,
				last_witness_status=EXCLUDED.last_witness_status,
				last_error_class=EXCLUDED.last_error_class,
				last_value_hash=EXCLUDED.last_value_hash,
				last_context_slot=EXCLUDED.last_context_slot,
				last_observed_at=now(),updated_at=now()
			RETURNING network,method,provider,observations,quorum_agreements,quorum_disagreements,
			          conflict_observations,unavailable_count,malformed_count,rate_limited_count,
			          last_witness_status,last_error_class,last_value_hash,last_context_slot,
			          trust_state,first_observed_at,last_observed_at
		`, network, method, provider,
			boolToProviderCount(observation.Agreement), boolToProviderCount(observation.Disagreement),
			boolToProviderCount(observation.Conflict), boolToProviderCount(observation.Unavailable),
			boolToProviderCount(observation.Malformed), boolToProviderCount(observation.RateLimited),
			strings.TrimSpace(witness.Status), strings.TrimSpace(witness.ErrorClass),
			strings.TrimSpace(witness.ValueHash), lastSlot,
		).Scan(
			&memory.Network, &memory.Method, &memory.Provider, &memory.Observations,
			&memory.QuorumAgreements, &memory.QuorumDisagreements, &memory.ConflictObservations,
			&memory.UnavailableCount, &memory.MalformedCount, &memory.RateLimitedCount,
			&memory.LastWitnessStatus, &memory.LastErrorClass, &memory.LastValueHash,
			&memory.LastContextSlot, &memory.TrustState, &memory.FirstObservedAt, &memory.LastObservedAt,
		)
		if err != nil {
			return err
		}
		state := deriveProviderWitnessTrustState(memory)
		if _, err := tx.ExecContext(ctx, `
			UPDATE security_provider_witness_memory
			SET trust_state=$4,updated_at=now()
			WHERE network=$1 AND method=$2 AND provider=$3
		`, network, method, provider, state); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func LoadProviderWitnessMemory(ctx context.Context, db *sql.DB, network, method string, limit int) (ProviderWitnessMemoryReport, error) {
	network = normalizeRadarNetwork(network)
	method = strings.TrimSpace(method)
	if db == nil {
		return ProviderWitnessMemoryReport{Network: network, Status: "database_unavailable", Providers: []ProviderWitnessMemory{}, Policy: providerWitnessMemoryPolicy()}, nil
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := db.QueryContext(ctx, `
		SELECT network,method,provider,observations,quorum_agreements,quorum_disagreements,
		       conflict_observations,unavailable_count,malformed_count,rate_limited_count,
		       last_witness_status,last_error_class,last_value_hash,last_context_slot,
		       trust_state,first_observed_at,last_observed_at
		FROM security_provider_witness_memory
		WHERE network=$1 AND ($2='' OR method=$2)
		ORDER BY
		  CASE trust_state
		    WHEN 'quarantine_candidate' THEN 5
		    WHEN 'divergent' THEN 4
		    WHEN 'availability_degraded' THEN 3
		    WHEN 'learning' THEN 2
		    WHEN 'consistent' THEN 1
		    ELSE 0
		  END DESC,
		  observations DESC,provider ASC
		LIMIT $3
	`, network, method, limit)
	if err != nil {
		return ProviderWitnessMemoryReport{}, err
	}
	defer rows.Close()
	providers := []ProviderWitnessMemory{}
	for rows.Next() {
		var item ProviderWitnessMemory
		if err := rows.Scan(
			&item.Network, &item.Method, &item.Provider, &item.Observations,
			&item.QuorumAgreements, &item.QuorumDisagreements, &item.ConflictObservations,
			&item.UnavailableCount, &item.MalformedCount, &item.RateLimitedCount,
			&item.LastWitnessStatus, &item.LastErrorClass, &item.LastValueHash,
			&item.LastContextSlot, &item.TrustState, &item.FirstObservedAt, &item.LastObservedAt,
		); err != nil {
			return ProviderWitnessMemoryReport{}, err
		}
		providers = append(providers, item)
	}
	if err := rows.Err(); err != nil {
		return ProviderWitnessMemoryReport{}, err
	}
	sort.SliceStable(providers, func(i, j int) bool {
		ri := providerWitnessTrustStateRank(providers[i].TrustState)
		rj := providerWitnessTrustStateRank(providers[j].TrustState)
		if ri != rj {
			return ri > rj
		}
		if providers[i].Observations != providers[j].Observations {
			return providers[i].Observations > providers[j].Observations
		}
		return providers[i].Provider < providers[j].Provider
	})
	status := "learning"
	for _, item := range providers {
		if item.TrustState == "quarantine_candidate" || item.TrustState == "divergent" {
			status = "attention_required"
			break
		}
		if item.TrustState == "availability_degraded" && status != "attention_required" {
			status = "degraded_availability"
		}
	}
	if len(providers) == 0 {
		status = "no_observations"
	}
	return ProviderWitnessMemoryReport{
		Available: len(providers) > 0, Network: network, Status: status,
		ProviderCount: len(providers), Providers: providers, GeneratedAt: time.Now().UTC(),
		Policy: providerWitnessMemoryPolicy(),
	}, nil
}

func providerWitnessMemoryPolicy() map[string]any {
	return map[string]any{
		"ruleset":                                ProviderWitnessMemoryRuleset,
		"numeric_trust_score_disabled":            true,
		"conflict_does_not_assign_fault":           true,
		"verified_quorum_required_for_disagreement": true,
		"memory_does_not_auto_remove_provider":      true,
		"provider_host_or_credentials_persisted":    false,
	}
}

func normalizeProviderWitnessLabel(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if len(value) > 80 || strings.ContainsAny(value, "/?#@") {
		return "unknown"
	}
	return value
}

func providerWitnessTrustStateRank(value string) int {
	switch strings.TrimSpace(value) {
	case "quarantine_candidate":
		return 5
	case "divergent":
		return 4
	case "availability_degraded":
		return 3
	case "learning":
		return 2
	case "consistent":
		return 1
	default:
		return 0
	}
}

func boolToProviderCount(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func ValidateProviderWitnessMemory(memory ProviderWitnessMemory) error {
	if memory.Observations < memory.QuorumAgreements+memory.QuorumDisagreements {
		return fmt.Errorf("provider witness counters exceed observations")
	}
	return nil
}
