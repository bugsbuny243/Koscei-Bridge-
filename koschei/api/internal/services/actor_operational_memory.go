package services

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

type ActorOperationalMatch struct {
	Wallet                    string   `json:"wallet"`
	Classification            string   `json:"classification"`
	EvidenceStatus            string   `json:"evidence_status"`
	Rules                     []string `json:"rules"`
	DirectVerifiedRelations   int      `json:"direct_verified_relations"`
	DirectObservedRelations   int      `json:"direct_observed_relations"`
	SharedCounterpartCount    int      `json:"shared_counterpart_count"`
	SharedRelationCount       int      `json:"shared_relation_count"`
	SubjectTokenContexts      int      `json:"subject_token_contexts"`
	CandidateTokenContexts    int      `json:"candidate_token_contexts"`
	SharedFundingSourceCount  int      `json:"shared_funding_source_count"`
	VerifiedOverlapCount      int      `json:"verified_overlap_count"`
}

type ActorOperationalMemoryReport struct {
	Wallet      string                  `json:"wallet"`
	Network     string                  `json:"network"`
	Available   bool                    `json:"available"`
	Status      string                  `json:"status"`
	MatchCount  int                     `json:"match_count"`
	Matches     []ActorOperationalMatch `json:"matches"`
	GeneratedAt time.Time               `json:"generated_at"`
	Policy      map[string]any          `json:"policy"`
}

type actorOperationalMatchStats struct {
	Wallet                   string
	DirectVerifiedRelations  int
	DirectObservedRelations  int
	SharedCounterpartCount   int
	SharedRelationCount      int
	SubjectTokenContexts     int
	CandidateTokenContexts   int
	SharedFundingSourceCount int
	VerifiedOverlapCount     int
}

func (s *ActorDefenseStore) LoadOperationalMemoryMatches(ctx context.Context, wallet, network string, limit int) (ActorOperationalMemoryReport, error) {
	wallet = strings.TrimSpace(wallet)
	network = normalizeRadarNetwork(network)
	if s == nil || s.DB == nil {
		return ActorOperationalMemoryReport{}, fmt.Errorf("actor defense database is unavailable")
	}
	if wallet == "" {
		return ActorOperationalMemoryReport{}, fmt.Errorf("actor wallet is required")
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}

	stats := map[string]*actorOperationalMatchStats{}
	ensure := func(candidate string) *actorOperationalMatchStats {
		candidate = strings.TrimSpace(candidate)
		row := stats[candidate]
		if row == nil {
			row = &actorOperationalMatchStats{Wallet: candidate}
			stats[candidate] = row
		}
		return row
	}

	if err := s.loadDirectOperationalLinks(ctx, wallet, network, ensure); err != nil {
		return ActorOperationalMemoryReport{}, err
	}
	if err := s.loadSharedOperationalOverlaps(ctx, wallet, network, ensure); err != nil {
		return ActorOperationalMemoryReport{}, err
	}

	matches := make([]ActorOperationalMatch, 0, len(stats))
	for candidate, row := range stats {
		if candidate == "" || candidate == wallet || row == nil {
			continue
		}
		match := classifyActorOperationalMatch(*row)
		if match.Classification == "none" {
			continue
		}
		matches = append(matches, match)
	}
	sort.SliceStable(matches, func(i, j int) bool {
		ri := actorOperationalClassificationRank(matches[i].Classification)
		rj := actorOperationalClassificationRank(matches[j].Classification)
		if ri != rj {
			return ri > rj
		}
		if matches[i].VerifiedOverlapCount != matches[j].VerifiedOverlapCount {
			return matches[i].VerifiedOverlapCount > matches[j].VerifiedOverlapCount
		}
		if matches[i].SharedCounterpartCount != matches[j].SharedCounterpartCount {
			return matches[i].SharedCounterpartCount > matches[j].SharedCounterpartCount
		}
		return matches[i].Wallet < matches[j].Wallet
	})
	if len(matches) > limit {
		matches = matches[:limit]
	}

	status := "no_operational_overlap"
	if len(matches) > 0 {
		status = "operational_overlap_observed"
	}
	return ActorOperationalMemoryReport{
		Wallet: wallet, Network: network, Available: len(matches) > 0,
		Status: status, MatchCount: len(matches), Matches: matches, GeneratedAt: time.Now().UTC(),
		Policy: map[string]any{
			"real_world_identity_claim":                    false,
			"same_operator_claim":                          false,
			"weighted_similarity_score":                    false,
			"single_shared_cex_or_service_is_not_a_match":  true,
			"observed_overlap_cannot_change_grade_alone":   true,
			"verified_direct_link_proves_interaction_only": true,
			"ruleset":                                      "koschei-actor-operational-memory-v1",
		},
	}, nil
}

func (s *ActorDefenseStore) loadDirectOperationalLinks(ctx context.Context, wallet, network string, ensure func(string) *actorOperationalMatchStats) error {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT counterpart_id,
		       count(*) FILTER (WHERE verification_status='verified')::integer AS verified_count,
		       count(*) FILTER (WHERE verification_status='observed')::integer AS observed_count
		FROM security_actor_evidence
		WHERE network=$2
		  AND actor_wallet=$1
		  AND counterpart_kind='wallet'
		  AND counterpart_id<>$1
		  AND verification_status IN ('verified','observed')
		  AND relation IN (
		      'direct_sol_transfer_in','direct_sol_transfer_out',
		      'direct_token_transfer_in','direct_token_transfer_out',
		      'funded_by','funding_origin','funded_creator'
		  )
		GROUP BY counterpart_id
	`, wallet, network)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var candidate string
		var verified, observed int
		if err := rows.Scan(&candidate, &verified, &observed); err != nil {
			return err
		}
		row := ensure(candidate)
		row.DirectVerifiedRelations += verified
		row.DirectObservedRelations += observed
	}
	return rows.Err()
}

func (s *ActorDefenseStore) loadSharedOperationalOverlaps(ctx context.Context, wallet, network string, ensure func(string) *actorOperationalMatchStats) error {
	rows, err := s.DB.QueryContext(ctx, `
		WITH subject AS (
			SELECT counterpart_id,relation,verification_status,COALESCE(token_mint,'') AS token_mint
			FROM security_actor_evidence
			WHERE network=$2
			  AND actor_wallet=$1
			  AND counterpart_kind='wallet'
			  AND verification_status IN ('verified','observed')
			  AND relation IN ('funded_by','funding_origin','initial_token_recipient','creator_recipient_in_window')
		), overlap AS (
			SELECT c.actor_wallet AS candidate_wallet,
			       s.counterpart_id,
			       s.relation,
			       s.verification_status AS subject_status,
			       c.verification_status AS candidate_status,
			       s.token_mint AS subject_token_mint,
			       COALESCE(c.token_mint,'') AS candidate_token_mint
			FROM subject s
			JOIN security_actor_evidence c
			  ON c.network=$2
			 AND c.actor_wallet<>$1
			 AND c.counterpart_kind='wallet'
			 AND c.counterpart_id=s.counterpart_id
			 AND c.relation=s.relation
			 AND c.verification_status IN ('verified','observed')
			WHERE lower(COALESCE(c.metadata->>'source_type','')) NOT IN ('cex','exchange','hot_wallet')
			  AND lower(COALESCE(c.metadata->>'identity_opaque','false'))<>'true'
		)
		SELECT candidate_wallet,
		       count(DISTINCT counterpart_id)::integer AS shared_counterparts,
		       count(DISTINCT relation)::integer AS shared_relations,
		       count(DISTINCT NULLIF(subject_token_mint,''))::integer AS subject_token_contexts,
		       count(DISTINCT NULLIF(candidate_token_mint,''))::integer AS candidate_token_contexts,
		       count(DISTINCT counterpart_id) FILTER (WHERE relation IN ('funded_by','funding_origin'))::integer AS shared_funding_sources,
		       count(*) FILTER (WHERE subject_status='verified' AND candidate_status='verified')::integer AS verified_overlap_count
		FROM overlap
		GROUP BY candidate_wallet
	`, wallet, network)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var candidate string
		var sharedCounterparts, sharedRelations, subjectTokens, candidateTokens, sharedFunding, verifiedOverlap int
		if err := rows.Scan(&candidate, &sharedCounterparts, &sharedRelations, &subjectTokens, &candidateTokens, &sharedFunding, &verifiedOverlap); err != nil {
			return err
		}
		row := ensure(candidate)
		row.SharedCounterpartCount = maxOperationalInt(row.SharedCounterpartCount, sharedCounterparts)
		row.SharedRelationCount = maxOperationalInt(row.SharedRelationCount, sharedRelations)
		row.SubjectTokenContexts = maxOperationalInt(row.SubjectTokenContexts, subjectTokens)
		row.CandidateTokenContexts = maxOperationalInt(row.CandidateTokenContexts, candidateTokens)
		row.SharedFundingSourceCount = maxOperationalInt(row.SharedFundingSourceCount, sharedFunding)
		row.VerifiedOverlapCount = maxOperationalInt(row.VerifiedOverlapCount, verifiedOverlap)
	}
	return rows.Err()
}

func classifyActorOperationalMatch(stats actorOperationalMatchStats) ActorOperationalMatch {
	out := ActorOperationalMatch{
		Wallet: stats.Wallet, Classification: "none", EvidenceStatus: "unverified", Rules: []string{},
		DirectVerifiedRelations: stats.DirectVerifiedRelations,
		DirectObservedRelations: stats.DirectObservedRelations,
		SharedCounterpartCount: stats.SharedCounterpartCount,
		SharedRelationCount: stats.SharedRelationCount,
		SubjectTokenContexts: stats.SubjectTokenContexts,
		CandidateTokenContexts: stats.CandidateTokenContexts,
		SharedFundingSourceCount: stats.SharedFundingSourceCount,
		VerifiedOverlapCount: stats.VerifiedOverlapCount,
	}
	if stats.DirectVerifiedRelations > 0 {
		out.Rules = append(out.Rules, "AOM-01")
		out.Classification = "verified_counterparty_link"
		out.EvidenceStatus = "verified"
	}
	if stats.SharedFundingSourceCount > 0 && stats.SubjectTokenContexts >= 2 && stats.CandidateTokenContexts >= 2 {
		out.Rules = append(out.Rules, "AOM-02")
		if out.Classification == "none" {
			out.Classification = "repeated_funding_overlap"
			out.EvidenceStatus = "observed"
		}
	}
	if stats.SharedCounterpartCount >= 2 && stats.SharedRelationCount >= 2 {
		out.Rules = append(out.Rules, "AOM-03")
		if out.Classification == "none" || out.Classification == "repeated_funding_overlap" {
			out.Classification = "repeated_operational_overlap"
			out.EvidenceStatus = "observed"
		}
	}
	if stats.DirectObservedRelations > 0 {
		out.Rules = append(out.Rules, "AOM-04")
		if out.Classification == "none" {
			out.Classification = "observed_counterparty_link"
			out.EvidenceStatus = "observed"
		}
	}
	if out.Classification == "none" && stats.SharedCounterpartCount > 0 {
		out.Rules = append(out.Rules, "AOM-05")
		out.Classification = "single_operational_overlap"
		out.EvidenceStatus = "observed"
	}
	return out
}

func actorOperationalClassificationRank(value string) int {
	switch strings.TrimSpace(value) {
	case "verified_counterparty_link":
		return 5
	case "repeated_operational_overlap":
		return 4
	case "repeated_funding_overlap":
		return 3
	case "observed_counterparty_link":
		return 2
	case "single_operational_overlap":
		return 1
	default:
		return 0
	}
}

func maxOperationalInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var _ *sql.DB
