package services

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// LoadPersistentWalletDossier assembles the investigation dossier from the
// all-time actor index. Raw radar tables are optional label sources only; actor
// relationships and observation windows never depend on raw-event retention.
func (s *ActorDefenseStore) LoadPersistentWalletDossier(ctx context.Context, wallet, network string, relationLimit int) (ActorDefenseDossier, error) {
	wallet = strings.TrimSpace(wallet)
	network = normalizeRadarNetwork(network)
	if s == nil || s.DB == nil {
		return ActorDefenseDossier{}, fmt.Errorf("actor defense database is unavailable")
	}
	if wallet == "" {
		return ActorDefenseDossier{}, fmt.Errorf("actor wallet is required")
	}
	if relationLimit <= 0 || relationLimit > 1000 {
		relationLimit = 500
	}

	builders := map[string]*actorDefenseTokenBuilder{}
	ensure := func(mint string) *actorDefenseTokenBuilder {
		mint = strings.TrimSpace(mint)
		row := builders[mint]
		if row == nil {
			row = &actorDefenseTokenBuilder{item: ActorDefenseTokenObservation{Mint: mint}, roles: map[string]bool{}}
			builders[mint] = row
		}
		return row
	}

	createdCount, err := s.loadPersistentCreatedTokens(ctx, wallet, network, ensure)
	if err != nil {
		return ActorDefenseDossier{}, err
	}
	dominantCount, err := s.loadPersistentDominantHolderTokens(ctx, wallet, network, ensure)
	if err != nil {
		return ActorDefenseDossier{}, err
	}
	tradedCount, err := s.loadTradedTokens(ctx, wallet, ensure)
	if err != nil {
		return ActorDefenseDossier{}, err
	}

	tokens := make([]ActorDefenseTokenObservation, 0, len(builders))
	for _, builder := range builders {
		for role := range builder.roles {
			builder.item.Roles = append(builder.item.Roles, role)
		}
		sort.Strings(builder.item.Roles)
		tokens = append(tokens, builder.item)
	}
	sort.SliceStable(tokens, func(i, j int) bool {
		if !tokens[i].LastObservedAt.Equal(tokens[j].LastObservedAt) {
			return tokens[i].LastObservedAt.After(tokens[j].LastObservedAt)
		}
		return tokens[i].Mint < tokens[j].Mint
	})

	related, err := s.loadPersistentRelatedActors(ctx, wallet, network, relationLimit)
	if err != nil {
		return ActorDefenseDossier{}, err
	}
	evidence, err := s.loadEvidence(ctx, wallet, network, relationLimit)
	if err != nil {
		return ActorDefenseDossier{}, err
	}
	verifiedCreatorTokens, err := s.countPersistentVerifiedCreatorTokens(ctx, wallet, network)
	if err != nil {
		return ActorDefenseDossier{}, err
	}
	verified, observed := 0, 0
	for _, row := range evidence {
		switch row.VerificationStatus {
		case "verified":
			verified++
		case "observed":
			observed++
		}
	}
	creatorReuseStatus := "observed"
	if verifiedCreatorTokens >= 2 {
		creatorReuseStatus = "verified"
	}

	track := ActorDefenseTrack{
		Network: network, TargetKind: "wallet", TargetID: wallet,
		CreatedTokenCount: createdCount, DominantHolderTokenCount: dominantCount,
		TradedTokenCount: tradedCount, RelatedActorCount: len(related),
		VerifiedEvidenceCount: verified, ObservedEvidenceCount: observed,
	}
	track.State = DeriveActorDefenseTrackState(track, related)
	track.Dossier = map[string]any{
		"token_count":                     len(tokens),
		"evidence_count":                  len(evidence),
		"actor_memory_scope":              "persistent_actor_index",
		"raw_event_retention_independent": true,
		"verified_creator_token_count":    verifiedCreatorTokens,
		"creator_reuse_evidence_status":   creatorReuseStatus,
		"holder_reuse_evidence_status":    "observed",
		"related_actor_evidence_status":   "observed",
		"state_basis":                     []string{"persistent_actor_evidence", "pump_trade_ledger", "signed_transaction_evidence"},
		"no_identity_or_intent_claim":     true,
	}
	if err := s.upsertTrack(ctx, &track); err != nil {
		return ActorDefenseDossier{}, err
	}

	return ActorDefenseDossier{
		Wallet: wallet, Network: network, Track: track, Tokens: tokens,
		RelatedActors: related, Evidence: evidence,
		Coverage: map[string]any{
			"created_tokens":                  createdCount,
			"verified_creator_tokens":         verifiedCreatorTokens,
			"dominant_holder_tokens":          dominantCount,
			"traded_tokens":                   tradedCount,
			"related_actors":                  len(related),
			"persisted_evidence":              len(evidence),
			"actor_memory_scope":              "persistent_actor_index",
			"raw_event_retention_independent": true,
		},
		Policy: map[string]any{
			"no_evidence_no_claim":                                           true,
			"wallet_addresses_are_case_sensitive":                            true,
			"verified_requires_transaction_or_owner_resolved_chain_evidence": true,
			"inferred_watch_only":                                            true,
			"unverified_excluded_from_grade":                                 true,
			"identity_or_wrongdoing_claim":                                   false,
		},
		GeneratedAt: time.Now().UTC(),
	}, nil
}

func (s *ActorDefenseStore) loadPersistentCreatedTokens(ctx context.Context, wallet, network string, ensure func(string) *actorDefenseTokenBuilder) (int, error) {
	rows, err := s.DB.QueryContext(ctx, `
		WITH memory AS (
			SELECT token_mint,
			       min(first_observed_at) AS first_seen_at,
			       max(last_observed_at) AS last_seen_at,
			       (array_agg(NULLIF(btrim(signature),'') ORDER BY last_observed_at DESC)
			          FILTER (WHERE signature IS NOT NULL AND btrim(signature)<>''))[1] AS signature
			FROM security_actor_evidence
			WHERE network=$2
			  AND actor_wallet=$1
			  AND actor_role='creator_deployer'
			  AND relation='created_token'
			  AND verification_status IN ('verified','observed')
			  AND token_mint IS NOT NULL
			  AND btrim(token_mint)<>''
			GROUP BY token_mint
		)
		SELECT m.token_mint,
		       COALESCE((
			   SELECT COALESCE(NULLIF(r.signals->>'token_name',''),NULLIF(r.raw_summary->>'name',''),'')
			   FROM security_radar_events r
			   WHERE r.network=$2 AND r.target=m.token_mint
			   ORDER BY r.created_at DESC
			   LIMIT 1
		       ),''),
		       COALESCE((
			   SELECT COALESCE(NULLIF(r.signals->>'token_symbol',''),NULLIF(r.raw_summary->>'symbol',''),'')
			   FROM security_radar_events r
			   WHERE r.network=$2 AND r.target=m.token_mint
			   ORDER BY r.created_at DESC
			   LIMIT 1
		       ),''),
		       m.first_seen_at,m.last_seen_at,COALESCE(m.signature,'')
		FROM memory m
		ORDER BY m.last_seen_at DESC,m.token_mint`, wallet, network)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var mint, name, symbol, signature string
		var firstAt, lastAt time.Time
		if err := rows.Scan(&mint, &name, &symbol, &firstAt, &lastAt, &signature); err != nil {
			return 0, err
		}
		row := ensure(mint)
		row.roles["creator_deployer"] = true
		row.item.Name = strings.TrimSpace(name)
		row.item.Symbol = strings.TrimSpace(symbol)
		row.item.CreatorSignature = strings.TrimSpace(signature)
		mergeActorDefenseTimes(&row.item, firstAt, lastAt)
		count++
	}
	return count, rows.Err()
}

func (s *ActorDefenseStore) countPersistentVerifiedCreatorTokens(ctx context.Context, wallet, network string) (int, error) {
	var count int
	err := s.DB.QueryRowContext(ctx, `
		SELECT count(DISTINCT token_mint)::integer
		FROM security_actor_evidence
		WHERE network=$2
		  AND actor_wallet=$1
		  AND actor_role='creator_deployer'
		  AND relation='created_token'
		  AND verification_status='verified'
		  AND token_mint IS NOT NULL
		  AND btrim(token_mint)<>''`, wallet, network).Scan(&count)
	return count, err
}

func (s *ActorDefenseStore) loadPersistentDominantHolderTokens(ctx context.Context, wallet, network string, ensure func(string) *actorDefenseTokenBuilder) (int, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT token_mint,
		       COALESCE(min(
			   CASE
			       WHEN COALESCE(metadata->>'best_holder_rank',metadata->>'holder_rank','') ~ '^[0-9]+$'
			       THEN COALESCE(metadata->>'best_holder_rank',metadata->>'holder_rank')::integer
			       ELSE NULL
			   END
		       ),0) AS holder_rank,
		       COALESCE(max(
			   CASE
			       WHEN COALESCE(metadata->>'max_holder_percentage',metadata->>'holder_percentage','') ~ '^[0-9]+([.][0-9]+)?$'
			       THEN COALESCE(metadata->>'max_holder_percentage',metadata->>'holder_percentage')::numeric
			       ELSE 0
			   END
		       ),0)::double precision AS percentage,
		       min(first_observed_at),max(last_observed_at)
		FROM security_actor_evidence
		WHERE network=$2
		  AND actor_wallet=$1
		  AND actor_role='dominant_holder'
		  AND relation='dominant_holder_of'
		  AND verification_status IN ('verified','observed')
		  AND token_mint IS NOT NULL
		  AND btrim(token_mint)<>''
		GROUP BY token_mint
		ORDER BY max(last_observed_at) DESC,token_mint`, wallet, network)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var mint string
		var rank int
		var percentage float64
		var firstAt, lastAt time.Time
		if err := rows.Scan(&mint, &rank, &percentage, &firstAt, &lastAt); err != nil {
			return 0, err
		}
		row := ensure(mint)
		row.roles["dominant_holder"] = true
		row.item.HolderRank = rank
		row.item.HolderPercentage = percentage
		mergeActorDefenseTimes(&row.item, firstAt, lastAt)
		count++
	}
	return count, rows.Err()
}

func (s *ActorDefenseStore) loadPersistentRelatedActors(ctx context.Context, wallet, network string, limit int) ([]ActorDefenseRelatedActor, error) {
	rows, err := s.DB.QueryContext(ctx, `
		WITH actor_tokens AS (
			SELECT DISTINCT token_mint
			FROM security_actor_evidence
			WHERE network=$2
			  AND actor_wallet=$1
			  AND actor_role IN ('creator_deployer','dominant_holder')
			  AND relation IN ('created_token','dominant_holder_of')
			  AND verification_status IN ('verified','observed')
			  AND token_mint IS NOT NULL
			  AND btrim(token_mint)<>''
		), holder_memory AS (
			SELECT network,actor_wallet,token_mint,
			       max(
			           CASE
			               WHEN COALESCE(metadata->>'max_holder_percentage',metadata->>'holder_percentage','') ~ '^[0-9]+([.][0-9]+)?$'
			               THEN COALESCE(metadata->>'max_holder_percentage',metadata->>'holder_percentage')::numeric
			               ELSE 0
			           END
			       )::double precision AS max_percentage,
			       min(first_observed_at) AS first_seen_at,
			       max(last_observed_at) AS last_seen_at
			FROM security_actor_evidence
			WHERE network=$2
			  AND actor_role='dominant_holder'
			  AND relation='dominant_holder_of'
			  AND verification_status IN ('verified','observed')
			  AND token_mint IS NOT NULL
			GROUP BY network,actor_wallet,token_mint
		)
		SELECT h.actor_wallet,count(DISTINCT h.token_mint),max(h.max_percentage),
		       min(h.first_seen_at),max(h.last_seen_at)
		FROM holder_memory h
		JOIN actor_tokens t ON t.token_mint=h.token_mint
		WHERE h.actor_wallet<>$1 AND h.max_percentage>=20
		GROUP BY h.actor_wallet
		ORDER BY count(DISTINCT h.token_mint) DESC,max(h.max_percentage) DESC,max(h.last_seen_at) DESC
		LIMIT $3`, wallet, network, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ActorDefenseRelatedActor{}
	for rows.Next() {
		var item ActorDefenseRelatedActor
		if err := rows.Scan(&item.Wallet, &item.SharedTokenCount, &item.MaxPercentage, &item.FirstObservedAt, &item.LastObservedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
