package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

const PersistentFundingClusterOutcomeMemoryVersion = "koschei-persistent-funding-cluster-outcome-memory-v1"

type PersistentFundingTokenOutcome struct {
	FundingSourceWallet       string   `json:"funding_source_wallet"`
	DirectSourceOfSubject     bool     `json:"direct_source_of_subject"`
	ActorWallet               string   `json:"actor_wallet"`
	Mint                      string   `json:"mint"`
	CreationEvidenceStatus    string   `json:"creation_evidence_status"`
	LifecycleObserved         bool     `json:"lifecycle_observed"`
	LifecycleFateStatus       string   `json:"lifecycle_fate_status"`
	LifecycleObservationCount int64    `json:"lifecycle_observation_count"`
	VerifiedLifecycleTransition bool   `json:"verified_lifecycle_transition"`
	SignedVerdictAvailable    bool     `json:"signed_verdict_available"`
	LatestSignedGrade         string   `json:"latest_signed_grade,omitempty"`
	LatestSignedVerdict       string   `json:"latest_signed_verdict,omitempty"`
	LatestSignedSignature     string   `json:"latest_signed_signature,omitempty"`
	LatestSignedVerdictAt     string   `json:"latest_signed_verdict_at,omitempty"`
	ExitEventCount            int      `json:"exit_event_count"`
	VerifiedExitEventCount    int      `json:"verified_exit_event_count"`
	ObservedExitEventCount    int      `json:"observed_exit_event_count"`
	ExitEventKinds            []string `json:"exit_event_kinds"`
	LastExitObservedAt        string   `json:"last_exit_observed_at,omitempty"`
}

type PersistentFundingClusterOutcomeReport struct {
	Version                    string                          `json:"version"`
	Network                    string                          `json:"network"`
	SubjectWallet              string                          `json:"subject_wallet"`
	Available                  bool                            `json:"available"`
	Complete                   bool                            `json:"complete"`
	Status                     string                          `json:"status"`
	FundingSourceCount         int                             `json:"funding_source_count"`
	FundedActorCount           int                             `json:"funded_actor_count"`
	TokenCount                 int                             `json:"token_count"`
	LifecycleCoveredTokenCount int                             `json:"lifecycle_covered_token_count"`
	InactiveOrDeadTokenCount   int                             `json:"inactive_or_dead_token_count"`
	VerifiedLifecycleTransitions int                           `json:"verified_lifecycle_transition_count"`
	SignedVerdictTokenCount    int                             `json:"signed_verdict_token_count"`
	ExitEvidenceTokenCount     int                             `json:"exit_evidence_token_count"`
	VerifiedExitEventCount     int                             `json:"verified_exit_event_count"`
	Outcomes                   []PersistentFundingTokenOutcome `json:"outcomes"`
	VerdictAuthority           bool                            `json:"verdict_authority"`
	SameOperatorClaim          bool                            `json:"same_operator_claim"`
	RealWorldIdentityClaim     bool                            `json:"real_world_identity_claim"`
	RugClaim                   bool                            `json:"rug_claim"`
	WrongdoingClaim            bool                            `json:"wrongdoing_claim"`
	Limitations                []string                        `json:"limitations"`
}

func NewPersistentFundingClusterOutcomeUnavailableReport(subject, network, status, limitation string) PersistentFundingClusterOutcomeReport {
	if strings.TrimSpace(status) == "" {
		status = "source_unavailable"
	}
	out := PersistentFundingClusterOutcomeReport{
		Version:       PersistentFundingClusterOutcomeMemoryVersion,
		Network:       normalizeRadarNetwork(network),
		SubjectWallet: strings.TrimSpace(subject),
		Status:        status,
		Outcomes:      []PersistentFundingTokenOutcome{},
		Limitations:   []string{},
	}
	if strings.TrimSpace(limitation) != "" {
		out.Limitations = append(out.Limitations, strings.TrimSpace(limitation))
	}
	return out
}

// LoadPersistentFundingClusterOutcomes joins three already-persisted evidence
// planes without creating a new verdict: creator-linked token lifecycle,
// signed deterministic Unified Radar verdict history, and transaction-referenced
// actor exit events. The output remains evidence-only and non-attributive.
func LoadPersistentFundingClusterOutcomes(ctx context.Context, db *sql.DB, subject, network string, limit int) (PersistentFundingClusterOutcomeReport, error) {
	subject = strings.TrimSpace(subject)
	network = normalizeRadarNetwork(network)
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	out := PersistentFundingClusterOutcomeReport{
		Version:       PersistentFundingClusterOutcomeMemoryVersion,
		Network:       network,
		SubjectWallet: subject,
		Complete:      true,
		Status:        "no_persistent_token_outcomes_observed",
		Outcomes:      []PersistentFundingTokenOutcome{},
		Limitations: []string{
			"Shared funding-source evidence does not prove common control, common identity, intent or wrongdoing.",
			"Lifecycle fate is limited to active versus inactive/dead observations; inactive/dead is not a rug classification.",
			"Only signed Unified Radar verdict rows with a non-empty signature are surfaced as signed verdict history.",
			"Exit-event memory requires a real transaction signature and positive slot and remains on-chain event evidence, not an attribution claim.",
		},
	}
	if subject == "" {
		out.Complete = false
		out.Status = "invalid_subject"
		out.Limitations = append(out.Limitations, "Subject wallet is empty; funding outcome memory was not queried.")
		return out, nil
	}
	if db == nil {
		return NewPersistentFundingClusterOutcomeUnavailableReport(subject, network, "source_unavailable", "Persistent actor database is unavailable."), nil
	}

	rows, err := db.QueryContext(ctx, persistentFundingClusterOutcomesSQL, network, subject, limit)
	if err != nil {
		if isSecurityRadarMissingRelation(err) {
			return NewPersistentFundingClusterOutcomeUnavailableReport(subject, network, "source_unavailable", "One or more persistent funding outcome evidence tables are unavailable."), nil
		}
		return out, err
	}
	defer rows.Close()

	fundingSources := map[string]bool{}
	fundedActors := map[string]bool{}
	for rows.Next() {
		var item PersistentFundingTokenOutcome
		var lifecycleFate sql.NullString
		var lifecycleObservations sql.NullInt64
		var lifecycleFirstLiquid, lifecycleInactiveSince sql.NullTime
		var verdictGrade, verdict, verdictSignature sql.NullString
		var verdictAt, lastExitAt sql.NullTime
		var exitCount, verifiedExitCount, observedExitCount int64
		var exitKindsJSON []byte
		if err := rows.Scan(
			&item.FundingSourceWallet,
			&item.DirectSourceOfSubject,
			&item.ActorWallet,
			&item.Mint,
			&item.CreationEvidenceStatus,
			&lifecycleFate,
			&lifecycleObservations,
			&lifecycleFirstLiquid,
			&lifecycleInactiveSince,
			&verdictGrade,
			&verdict,
			&verdictSignature,
			&verdictAt,
			&exitCount,
			&verifiedExitCount,
			&observedExitCount,
			&exitKindsJSON,
			&lastExitAt,
		); err != nil {
			return out, err
		}

		item.FundingSourceWallet = strings.TrimSpace(item.FundingSourceWallet)
		item.ActorWallet = strings.TrimSpace(item.ActorWallet)
		item.Mint = strings.TrimSpace(item.Mint)
		item.ExitEventKinds = []string{}
		if lifecycleFate.Valid {
			item.LifecycleObserved = true
			item.LifecycleFateStatus = strings.TrimSpace(lifecycleFate.String)
			item.LifecycleObservationCount = lifecycleObservations.Int64
		} else {
			item.LifecycleFateStatus = "unobserved"
		}
		item.VerifiedLifecycleTransition = lifecycleFirstLiquid.Valid && lifecycleInactiveSince.Valid && !lifecycleInactiveSince.Time.Before(lifecycleFirstLiquid.Time)
		if verdict.Valid && verdictSignature.Valid && strings.TrimSpace(verdictSignature.String) != "" {
			item.SignedVerdictAvailable = true
			item.LatestSignedGrade = strings.TrimSpace(verdictGrade.String)
			item.LatestSignedVerdict = strings.TrimSpace(verdict.String)
			item.LatestSignedSignature = strings.TrimSpace(verdictSignature.String)
			if verdictAt.Valid {
				item.LatestSignedVerdictAt = verdictAt.Time.UTC().Format(time.RFC3339)
			}
		}
		item.ExitEventCount = int(exitCount)
		item.VerifiedExitEventCount = int(verifiedExitCount)
		item.ObservedExitEventCount = int(observedExitCount)
		if len(exitKindsJSON) > 0 {
			var kinds []string
			if json.Unmarshal(exitKindsJSON, &kinds) == nil {
				item.ExitEventKinds = uniqueSortedFundingOutcomeStrings(kinds)
			}
		}
		if lastExitAt.Valid {
			item.LastExitObservedAt = lastExitAt.Time.UTC().Format(time.RFC3339)
		}

		fundingSources[item.FundingSourceWallet] = true
		fundedActors[item.ActorWallet] = true
		out.Outcomes = append(out.Outcomes, item)
		if item.LifecycleObserved {
			out.LifecycleCoveredTokenCount++
		}
		if item.LifecycleFateStatus == ActorTokenFateInactiveOrDead {
			out.InactiveOrDeadTokenCount++
		}
		if item.VerifiedLifecycleTransition {
			out.VerifiedLifecycleTransitions++
		}
		if item.SignedVerdictAvailable {
			out.SignedVerdictTokenCount++
		}
		if item.ExitEventCount > 0 {
			out.ExitEvidenceTokenCount++
		}
		out.VerifiedExitEventCount += item.VerifiedExitEventCount
	}
	if err := rows.Err(); err != nil {
		return out, err
	}

	out.FundingSourceCount = len(fundingSources)
	out.FundedActorCount = len(fundedActors)
	out.TokenCount = len(out.Outcomes)
	out.Available = out.TokenCount > 0
	if out.Available {
		out.Status = "persistent_token_outcomes_observed"
	}
	return out, nil
}

func uniqueSortedFundingOutcomeStrings(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = true
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

const persistentFundingClusterOutcomesSQL = `
WITH funding_sources AS (
	SELECT counterpart_id AS source_wallet,true AS direct_source_of_subject
	FROM security_actor_evidence
	WHERE network=$1
	  AND actor_wallet=$2
	  AND actor_role='funded_wallet'
	  AND counterpart_kind='wallet'
	  AND relation IN ('initial_funding_in','oldest_funding_in_window')
	  AND verification_status IN ('verified','observed')
	  AND btrim(counterpart_id)<>''
	  AND counterpart_id<>actor_wallet
	UNION ALL
	SELECT $2 AS source_wallet,false AS direct_source_of_subject
	WHERE EXISTS (
		SELECT 1 FROM security_actor_evidence
		WHERE network=$1
		  AND actor_role='funded_wallet'
		  AND counterpart_kind='wallet'
		  AND counterpart_id=$2
		  AND actor_wallet<>$2
		  AND relation IN ('initial_funding_in','oldest_funding_in_window')
		  AND verification_status IN ('verified','observed')
	)
), normalized_sources AS (
	SELECT source_wallet,bool_or(direct_source_of_subject) AS direct_source_of_subject
	FROM funding_sources
	WHERE btrim(source_wallet)<>''
	GROUP BY source_wallet
), funded_actors AS (
	SELECT
		s.source_wallet,
		s.direct_source_of_subject,
		e.actor_wallet AS funded_wallet
	FROM normalized_sources s
	JOIN security_actor_evidence e
	  ON e.network=$1
	 AND e.actor_role='funded_wallet'
	 AND e.counterpart_kind='wallet'
	 AND e.counterpart_id=s.source_wallet
	 AND e.actor_wallet<>s.source_wallet
	 AND e.relation IN ('initial_funding_in','oldest_funding_in_window')
	 AND e.verification_status IN ('verified','observed')
	GROUP BY s.source_wallet,s.direct_source_of_subject,e.actor_wallet
), token_candidates AS (
	SELECT
		f.source_wallet,
		f.direct_source_of_subject,
		f.funded_wallet,
		COALESCE(NULLIF(btrim(e.token_mint),''),CASE WHEN e.counterpart_kind='token' THEN NULLIF(btrim(e.counterpart_id),'') ELSE NULL END) AS mint,
		CASE WHEN bool_or(e.verification_status='verified') THEN 'verified' ELSE 'observed' END AS creation_evidence_status
	FROM funded_actors f
	JOIN security_actor_evidence e
	  ON e.network=$1
	 AND e.actor_wallet=f.funded_wallet
	 AND e.actor_role='creator_deployer'
	 AND e.relation='created_token'
	 AND e.verification_status IN ('verified','observed')
	GROUP BY f.source_wallet,f.direct_source_of_subject,f.funded_wallet,
		COALESCE(NULLIF(btrim(e.token_mint),''),CASE WHEN e.counterpart_kind='token' THEN NULLIF(btrim(e.counterpart_id),'') ELSE NULL END)
	UNION ALL
	SELECT
		f.source_wallet,
		f.direct_source_of_subject,
		f.funded_wallet,
		l.mint,
		'lifecycle_observed' AS creation_evidence_status
	FROM funded_actors f
	JOIN security_actor_token_lifecycle l
	  ON l.network=$1 AND l.actor_wallet=f.funded_wallet
), tokens AS (
	SELECT
		source_wallet,
		bool_or(direct_source_of_subject) AS direct_source_of_subject,
		funded_wallet,
		mint,
		CASE
			WHEN bool_or(creation_evidence_status='verified') THEN 'verified'
			WHEN bool_or(creation_evidence_status='observed') THEN 'observed'
			ELSE 'lifecycle_observed'
		END AS creation_evidence_status
	FROM token_candidates
	WHERE mint IS NOT NULL AND btrim(mint)<>''
	GROUP BY source_wallet,funded_wallet,mint
)
SELECT
	t.source_wallet,
	t.direct_source_of_subject,
	t.funded_wallet,
	t.mint,
	t.creation_evidence_status,
	l.fate_status,
	l.observation_count,
	l.first_liquid_observed_at,
	l.current_inactive_since,
	v.grade,
	v.verdict,
	v.signature,
	v.last_seen_at,
	COALESCE(x.exit_event_count,0)::bigint,
	COALESCE(x.verified_exit_event_count,0)::bigint,
	COALESCE(x.observed_exit_event_count,0)::bigint,
	COALESCE(x.exit_event_kinds,'[]'::jsonb),
	x.last_exit_observed_at
FROM tokens t
LEFT JOIN security_actor_token_lifecycle l
  ON l.network=$1 AND l.actor_wallet=t.funded_wallet AND l.mint=t.mint
LEFT JOIN LATERAL (
	SELECT grade,verdict,signature,last_seen_at
	FROM security_unified_radar_verdicts
	WHERE network=$1
	  AND target_kind='token'
	  AND target_id=t.mint
	  AND signed=true
	  AND signature IS NOT NULL
	  AND btrim(signature)<>''
	ORDER BY last_seen_at DESC,created_at DESC,id DESC
	LIMIT 1
) v ON true
LEFT JOIN LATERAL (
	SELECT
		count(*)::bigint AS exit_event_count,
		count(*) FILTER (WHERE evidence_state='verified')::bigint AS verified_exit_event_count,
		count(*) FILTER (WHERE evidence_state='observed')::bigint AS observed_exit_event_count,
		COALESCE(jsonb_agg(event_kind ORDER BY event_kind,observed_at,signature),'[]'::jsonb) AS exit_event_kinds,
		max(observed_at) AS last_exit_observed_at
	FROM security_actor_exit_events
	WHERE network=$1 AND actor_wallet=t.funded_wallet AND target=t.mint
) x ON true
ORDER BY
	t.direct_source_of_subject DESC,
	CASE WHEN COALESCE(x.verified_exit_event_count,0)>0 THEN 1 ELSE 0 END DESC,
	CASE WHEN v.signature IS NOT NULL THEN 1 ELSE 0 END DESC,
	COALESCE(x.last_exit_observed_at,l.last_observed_at) DESC NULLS LAST,
	t.source_wallet ASC,
	t.funded_wallet ASC,
	t.mint ASC
LIMIT $3`
