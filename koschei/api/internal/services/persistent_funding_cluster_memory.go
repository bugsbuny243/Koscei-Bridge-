package services

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

const PersistentFundingClusterMemoryVersion = "koschei-persistent-funding-cluster-memory-v1"

type PersistentFundingClusterMember struct {
	Wallet                        string    `json:"wallet"`
	FundingEvidenceStatus         string    `json:"funding_evidence_status"`
	CreatedTokenCount             int       `json:"created_token_count"`
	DominantHolderTokenCount      int       `json:"dominant_holder_token_count"`
	LiquidityRemovalEvidenceCount int       `json:"liquidity_removal_evidence_count"`
	ThreatTrackState              string    `json:"threat_track_state,omitempty"`
	FirstFundingObservedAt        time.Time `json:"first_funding_observed_at"`
	LastFundingObservedAt         time.Time `json:"last_funding_observed_at"`
}

type PersistentFundingSourceHistory struct {
	Wallet                   string                           `json:"wallet"`
	DirectSourceOfSubject    bool                             `json:"direct_source_of_subject"`
	EvidenceStatus           string                           `json:"evidence_status"`
	FundedActorCount         int                              `json:"funded_actor_count"`
	VerifiedFundedActorCount int                              `json:"verified_funded_actor_count"`
	ObservedFundedActorCount int                              `json:"observed_funded_actor_count"`
	CreatorActorCount        int                              `json:"creator_actor_count"`
	CreatedTokenCount        int                              `json:"created_token_count"`
	RepeatCreatorCount       int                              `json:"repeat_creator_count"`
	DominantHolderActorCount int                              `json:"dominant_holder_actor_count"`
	LiquidityRemovalActors   int                              `json:"liquidity_removal_actor_count"`
	CorrelatedTrackCount     int                              `json:"correlated_track_count"`
	VerifiedTrackCount       int                              `json:"verified_track_count"`
	AlertedTrackCount        int                              `json:"alerted_track_count"`
	FirstObservedAt          time.Time                        `json:"first_observed_at"`
	LastObservedAt           time.Time                        `json:"last_observed_at"`
	Members                  []PersistentFundingClusterMember `json:"members"`
	Limitations              []string                         `json:"limitations"`
}

type PersistentFundingClusterReport struct {
	Version                string                           `json:"version"`
	Network                string                           `json:"network"`
	SubjectWallet          string                           `json:"subject_wallet"`
	Available              bool                             `json:"available"`
	Complete               bool                             `json:"complete"`
	Status                 string                           `json:"status"`
	SourceCount            int                              `json:"source_count"`
	Sources                []PersistentFundingSourceHistory `json:"sources"`
	VerdictAuthority       bool                             `json:"verdict_authority"`
	SameOperatorClaim      bool                             `json:"same_operator_claim"`
	RealWorldIdentityClaim bool                             `json:"real_world_identity_claim"`
	WrongdoingClaim        bool                             `json:"wrongdoing_claim"`
	Limitations            []string                         `json:"limitations"`
}

func NewPersistentFundingClusterUnavailableReport(subject, network, status, limitation string) PersistentFundingClusterReport {
	if strings.TrimSpace(status) == "" {
		status = "source_unavailable"
	}
	out := PersistentFundingClusterReport{
		Version:       PersistentFundingClusterMemoryVersion,
		Network:       normalizeRadarNetwork(network),
		SubjectWallet: strings.TrimSpace(subject),
		Status:        status,
		Sources:       []PersistentFundingSourceHistory{},
		Limitations:   []string{},
	}
	if strings.TrimSpace(limitation) != "" {
		out.Limitations = append(out.Limitations, strings.TrimSpace(limitation))
	}
	return out
}

// LoadPersistentFundingClusterHistory answers a question that raw RPC providers
// do not: which other on-chain actors were funded by the same observed funding
// source and what persisted Koschei behavior was later observed for them.
//
// The report is deliberately non-authoritative. A shared funder is an on-chain
// relation, not proof of common control, common identity, intent or wrongdoing.
func LoadPersistentFundingClusterHistory(ctx context.Context, db *sql.DB, subject, network string, sourceLimit, memberLimit int) (PersistentFundingClusterReport, error) {
	subject = strings.TrimSpace(subject)
	network = normalizeRadarNetwork(network)
	if sourceLimit <= 0 || sourceLimit > 32 {
		sourceLimit = 8
	}
	if memberLimit <= 0 || memberLimit > 100 {
		memberLimit = 25
	}
	out := PersistentFundingClusterReport{
		Version:       PersistentFundingClusterMemoryVersion,
		Network:       network,
		SubjectWallet: subject,
		Status:        "no_persistent_funding_source_observed",
		Complete:      true,
		Sources:       []PersistentFundingSourceHistory{},
		Limitations: []string{
			"Shared funding-source evidence is an on-chain wallet relation and does not prove common control, common identity, intent or wrongdoing.",
			"initial_funding_in requires a completed funding-history walk; oldest_funding_in_window remains bounded-window evidence.",
			"Threat-track states summarize Koschei's retained evidence and are not real-world attribution claims.",
		},
	}
	if subject == "" {
		out.Status = "invalid_subject"
		out.Complete = false
		out.Limitations = append(out.Limitations, "Subject wallet is empty; funding-cluster memory was not queried.")
		return out, nil
	}
	if db == nil {
		return NewPersistentFundingClusterUnavailableReport(subject, network, "source_unavailable", "Persistent actor database is unavailable."), nil
	}

	rows, err := db.QueryContext(ctx, `
		WITH candidates AS (
			SELECT counterpart_id AS wallet, true AS direct_subject_source
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
			SELECT $2 AS wallet, false AS direct_subject_source
			WHERE EXISTS (
				SELECT 1
				FROM security_actor_evidence
				WHERE network=$1
				  AND actor_role='funded_wallet'
				  AND counterpart_kind='wallet'
				  AND counterpart_id=$2
				  AND actor_wallet<>$2
				  AND relation IN ('initial_funding_in','oldest_funding_in_window')
				  AND verification_status IN ('verified','observed')
			)
		)
		SELECT wallet,bool_or(direct_subject_source)
		FROM candidates
		WHERE btrim(wallet)<>''
		GROUP BY wallet
		ORDER BY bool_or(direct_subject_source) DESC,wallet ASC
		LIMIT $3`, network, subject, sourceLimit)
	if err != nil {
		// Keep a missing/partially migrated actor schema from taking down the
		// unified investigation surface.
		if isSecurityRadarMissingRelation(err) {
			return NewPersistentFundingClusterUnavailableReport(subject, network, "source_unavailable", "Persistent funding-cluster source schema is unavailable."), nil
		}
		return out, err
	}
	defer rows.Close()

	type candidate struct {
		wallet string
		direct bool
	}
	candidates := []candidate{}
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.wallet, &item.direct); err != nil {
			return out, err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}

	for _, item := range candidates {
		history, err := loadPersistentFundingSourceHistory(ctx, db, network, item.wallet, item.direct, memberLimit)
		if err != nil {
			if isSecurityRadarMissingRelation(err) {
				return NewPersistentFundingClusterUnavailableReport(subject, network, "source_unavailable", "Persistent funding-cluster history schema is unavailable."), nil
			}
			return out, err
		}
		out.Sources = append(out.Sources, history)
	}
	out.SourceCount = len(out.Sources)
	out.Available = out.SourceCount > 0
	if out.Available {
		out.Status = "persistent_funding_history_observed"
	}
	return out, nil
}

func loadPersistentFundingSourceHistory(ctx context.Context, db *sql.DB, network, funder string, directSource bool, memberLimit int) (PersistentFundingSourceHistory, error) {
	out := PersistentFundingSourceHistory{
		Wallet:                strings.TrimSpace(funder),
		DirectSourceOfSubject: directSource,
		EvidenceStatus:        "observed_supported",
		Members:               []PersistentFundingClusterMember{},
		Limitations: []string{
			"Members are grouped by a shared observed funding-source wallet only; the grouping is not an operator-identity claim.",
		},
	}

	var fundedActors, verifiedFunded, observedFunded int64
	var creatorActors, createdTokens, repeatCreators int64
	var dominantActors, liquidityActors int64
	var correlatedTracks, verifiedTracks, alertedTracks int64
	err := db.QueryRowContext(ctx, fundingClusterAggregateSQL, network, out.Wallet).Scan(
		&fundedActors, &verifiedFunded, &observedFunded,
		&creatorActors, &createdTokens, &repeatCreators,
		&dominantActors, &liquidityActors,
		&correlatedTracks, &verifiedTracks, &alertedTracks,
		&out.FirstObservedAt, &out.LastObservedAt,
	)
	if err != nil {
		return out, err
	}
	out.FundedActorCount = int(fundedActors)
	out.VerifiedFundedActorCount = int(verifiedFunded)
	out.ObservedFundedActorCount = int(observedFunded)
	out.CreatorActorCount = int(creatorActors)
	out.CreatedTokenCount = int(createdTokens)
	out.RepeatCreatorCount = int(repeatCreators)
	out.DominantHolderActorCount = int(dominantActors)
	out.LiquidityRemovalActors = int(liquidityActors)
	out.CorrelatedTrackCount = int(correlatedTracks)
	out.VerifiedTrackCount = int(verifiedTracks)
	out.AlertedTrackCount = int(alertedTracks)
	if out.VerifiedFundedActorCount > 0 {
		out.EvidenceStatus = "verified_supported"
	}

	rows, err := db.QueryContext(ctx, fundingClusterMembersSQL, network, out.Wallet, memberLimit)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var item PersistentFundingClusterMember
		var createdTokens, dominantTokens, liquidityEvidence int64
		if err := rows.Scan(
			&item.Wallet, &item.FundingEvidenceStatus,
			&createdTokens, &dominantTokens, &liquidityEvidence,
			&item.ThreatTrackState, &item.FirstFundingObservedAt, &item.LastFundingObservedAt,
		); err != nil {
			return out, err
		}
		item.CreatedTokenCount = int(createdTokens)
		item.DominantHolderTokenCount = int(dominantTokens)
		item.LiquidityRemovalEvidenceCount = int(liquidityEvidence)
		out.Members = append(out.Members, item)
	}
	return out, rows.Err()
}

const fundingClusterCTE = `
WITH funding_edges AS (
	SELECT
		actor_wallet AS funded_wallet,
		CASE WHEN bool_or(verification_status='verified') THEN 'verified' ELSE 'observed' END AS funding_status,
		min(first_observed_at) AS first_seen_at,
		max(last_observed_at) AS last_seen_at
	FROM security_actor_evidence
	WHERE network=$1
	  AND actor_role='funded_wallet'
	  AND counterpart_kind='wallet'
	  AND counterpart_id=$2
	  AND actor_wallet<>$2
	  AND relation IN ('initial_funding_in','oldest_funding_in_window')
	  AND verification_status IN ('verified','observed')
	GROUP BY actor_wallet
), creator_rollup AS (
	SELECT actor_wallet AS wallet,count(DISTINCT token_mint)::bigint AS created_token_count
	FROM security_actor_evidence
	WHERE network=$1
	  AND actor_role='creator_deployer'
	  AND relation='created_token'
	  AND verification_status IN ('verified','observed')
	  AND token_mint IS NOT NULL AND btrim(token_mint)<>''
	GROUP BY actor_wallet
), dominant_rollup AS (
	SELECT actor_wallet AS wallet,count(DISTINCT token_mint)::bigint AS dominant_token_count
	FROM security_actor_evidence
	WHERE network=$1
	  AND actor_role='dominant_holder'
	  AND relation='dominant_holder_of'
	  AND verification_status IN ('verified','observed')
	  AND token_mint IS NOT NULL AND btrim(token_mint)<>''
	GROUP BY actor_wallet
), liquidity_rollup AS (
	SELECT actor_wallet AS wallet,count(*)::bigint AS liquidity_evidence_count
	FROM security_actor_evidence
	WHERE network=$1
	  AND relation='liquidity_remove_activity'
	  AND verification_status IN ('verified','observed')
	GROUP BY actor_wallet
), joined AS (
	SELECT
		f.funded_wallet,f.funding_status,f.first_seen_at,f.last_seen_at,
		COALESCE(c.created_token_count,0)::bigint AS created_token_count,
		COALESCE(d.dominant_token_count,0)::bigint AS dominant_token_count,
		COALESCE(l.liquidity_evidence_count,0)::bigint AS liquidity_evidence_count,
		COALESCE(t.state,'') AS track_state
	FROM funding_edges f
	LEFT JOIN creator_rollup c ON c.wallet=f.funded_wallet
	LEFT JOIN dominant_rollup d ON d.wallet=f.funded_wallet
	LEFT JOIN liquidity_rollup l ON l.wallet=f.funded_wallet
	LEFT JOIN security_threat_tracks t
	  ON t.network=$1 AND t.target_kind='wallet' AND t.target_id=f.funded_wallet
)`

const fundingClusterAggregateSQL = fundingClusterCTE + `
SELECT
	count(*)::bigint,
	count(*) FILTER (WHERE funding_status='verified')::bigint,
	count(*) FILTER (WHERE funding_status='observed')::bigint,
	count(*) FILTER (WHERE created_token_count>0)::bigint,
	COALESCE(sum(created_token_count),0)::bigint,
	count(*) FILTER (WHERE created_token_count>=2)::bigint,
	count(*) FILTER (WHERE dominant_token_count>0)::bigint,
	count(*) FILTER (WHERE liquidity_evidence_count>0)::bigint,
	count(*) FILTER (WHERE lower(track_state)='correlated')::bigint,
	count(*) FILTER (WHERE lower(track_state)='verified')::bigint,
	count(*) FILTER (WHERE lower(track_state)='alerted')::bigint,
	min(first_seen_at),max(last_seen_at)
FROM joined`

const fundingClusterMembersSQL = fundingClusterCTE + `
SELECT
	funded_wallet,funding_status,created_token_count,dominant_token_count,
	liquidity_evidence_count,track_state,first_seen_at,last_seen_at
FROM joined
ORDER BY
	CASE lower(track_state)
		WHEN 'alerted' THEN 5 WHEN 'verified' THEN 4 WHEN 'correlated' THEN 3
		WHEN 'tracked' THEN 2 WHEN 'detected' THEN 1 ELSE 0
	END DESC,
	created_token_count DESC,
	last_seen_at DESC,
	funded_wallet ASC
LIMIT $3`
