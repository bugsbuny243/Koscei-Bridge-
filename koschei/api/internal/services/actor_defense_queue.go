package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ActorDefenseQueueItem is sorted by an explicit rule band. It contains no
// weighted priority, probability or wallet-risk number.
type ActorDefenseQueueItem struct {
	Track             ActorDefenseTrack       `json:"track"`
	RuleVerdict       ActorDefenseRuleVerdict `json:"rule_verdict"`
	VerificationBand  string                  `json:"verification_band"`
	BandReason        string                  `json:"band_reason"`
	NextAction        string                  `json:"next_action"`
	NeedsLiveEvidence bool                    `json:"needs_live_evidence"`
}

type ActorDefenseQueue struct {
	Items       []ActorDefenseQueueItem `json:"items"`
	Counts      map[string]int64        `json:"counts"`
	Total       int64                   `json:"total"`
	Network     string                  `json:"network"`
	StateFilter string                  `json:"state_filter,omitempty"`
	GeneratedAt time.Time               `json:"generated_at"`
	Policy      map[string]any          `json:"policy"`
}

func (s *ActorDefenseStore) ListVerificationQueue(ctx context.Context, network, state string, limit, offset int) (ActorDefenseQueue, error) {
	if s == nil || s.DB == nil {
		return ActorDefenseQueue{}, fmt.Errorf("actor defense database is unavailable")
	}
	network = normalizeRadarNetwork(network)
	state = strings.ToLower(strings.TrimSpace(state))
	if state != "" && actorDefenseStateRank(state) == 0 {
		return ActorDefenseQueue{}, fmt.Errorf("invalid actor defense state")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 || offset > 10000 {
		offset = 0
	}

	counts, total, err := s.actorDefenseQueueCounts(ctx, network)
	if err != nil {
		return ActorDefenseQueue{}, err
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id::text,network,target_kind,target_id,state,
		       created_token_count,dominant_holder_token_count,traded_token_count,
		       related_actor_count,verified_evidence_count,observed_evidence_count,
		       dossier,first_seen_at,last_seen_at,last_investigated_at
		FROM security_threat_tracks
		WHERE network=$1 AND ($2='' OR state=$2)
		ORDER BY
			CASE
				WHEN dossier->'rule_verdict'->>'verdict'='hard_trigger' THEN 0
				WHEN dossier->'rule_verdict'->>'verdict'='compounding_rule' THEN 1
				WHEN (
					(created_token_count>=2 AND dominant_holder_token_count>=2) OR
					(created_token_count>=2 AND related_actor_count>0) OR
					(dominant_holder_token_count>=2 AND related_actor_count>0)
				) THEN 1
				WHEN state='correlated' THEN 2
				WHEN dossier->'rule_verdict'->>'verdict'='watch_only' THEN 3
				WHEN state IN ('verified','alerted') THEN 4
				WHEN state='tracked' THEN 5
				ELSE 6
			END,
			last_seen_at DESC,
			id DESC
		LIMIT $3 OFFSET $4`, network, state, limit, offset)
	if err != nil {
		return ActorDefenseQueue{}, err
	}
	defer rows.Close()

	items := make([]ActorDefenseQueueItem, 0, limit)
	for rows.Next() {
		var track ActorDefenseTrack
		var dossierRaw []byte
		if err := rows.Scan(
			&track.ID, &track.Network, &track.TargetKind, &track.TargetID, &track.State,
			&track.CreatedTokenCount, &track.DominantHolderTokenCount, &track.TradedTokenCount,
			&track.RelatedActorCount, &track.VerifiedEvidenceCount, &track.ObservedEvidenceCount,
			&dossierRaw, &track.FirstSeenAt, &track.LastSeenAt, &track.LastInvestigatedAt,
		); err != nil {
			return ActorDefenseQueue{}, err
		}
		track.Dossier = map[string]any{}
		if len(dossierRaw) > 0 {
			_ = json.Unmarshal(dossierRaw, &track.Dossier)
		}
		verdict, ok := ActorDefenseRuleVerdictFromDossier(track.Dossier)
		if !ok || verdict.RulesetVersion != ActorDefenseRulesetVersion {
			verdict = EvaluateActorDefenseRules(track, nil)
		}
		band, reason := ActorDefenseVerificationBand(track, verdict)
		items = append(items, ActorDefenseQueueItem{
			Track:             track,
			RuleVerdict:       verdict,
			VerificationBand:  band,
			BandReason:        reason,
			NextAction:        ActorDefenseRuleNextAction(track, verdict),
			NeedsLiveEvidence: actorDefenseNeedsLiveEvidence(track, verdict),
		})
	}
	if err := rows.Err(); err != nil {
		return ActorDefenseQueue{}, err
	}

	return ActorDefenseQueue{
		Items: items, Counts: counts, Total: total, Network: network, StateFilter: state,
		GeneratedAt: time.Now().UTC(),
		Policy: map[string]any{
			"ruleset_version":                 ActorDefenseRulesetVersion,
			"numeric_score":                   false,
			"weighted_formula":                false,
			"queue_order":                     []string{"hard_trigger", "compounding", "evidence_pending", "watch", "verified_review", "monitor"},
			"inferred_policy":                 "watch_only",
			"unverified_policy":               "excluded",
			"no_identity_or_wrongdoing_claim": true,
		},
	}, nil
}

func (s *ActorDefenseStore) actorDefenseQueueCounts(ctx context.Context, network string) (map[string]int64, int64, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT state,count(*)
		FROM security_threat_tracks
		WHERE network=$1
		GROUP BY state`, network)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	counts := map[string]int64{"detected": 0, "tracked": 0, "correlated": 0, "verified": 0, "alerted": 0}
	var total int64
	for rows.Next() {
		var state string
		var count int64
		if err := rows.Scan(&state, &count); err != nil {
			return nil, 0, err
		}
		counts[state] = count
		total += count
	}
	return counts, total, rows.Err()
}

func ActorDefenseVerificationBand(track ActorDefenseTrack, verdict ActorDefenseRuleVerdict) (string, string) {
	switch verdict.Verdict {
	case "hard_trigger":
		return "hard_trigger", actorRuleIDList(verdict.TriggeredRules, "hard_trigger")
	case "compounding_rule":
		return "compounding", actorRuleIDList(verdict.TriggeredRules, "compounding")
	}
	if strings.EqualFold(track.State, "correlated") {
		return "evidence_pending", "cross-token correlation requires live transaction verification"
	}
	if verdict.Verdict == "watch_only" || len(verdict.WatchFlags) > 0 {
		return "watch", actorRuleIDList(verdict.WatchFlags, "watch")
	}
	if track.VerifiedEvidenceCount > 0 || strings.EqualFold(track.State, "verified") || strings.EqualFold(track.State, "alerted") {
		return "verified_review", "verified evidence is ready for owner review"
	}
	return "monitor", "no grade-changing rule is currently satisfied"
}

func ActorDefenseRuleNextAction(track ActorDefenseTrack, verdict ActorDefenseRuleVerdict) string {
	for _, hit := range verdict.TriggeredRules {
		switch hit.RuleID {
		case ActorRuleHardCreatorHolderFunding:
			return "review_verified_creator_holder_funding"
		case ActorRuleHardCreatorLiquidityRemoval:
			return "review_verified_creator_liquidity_removal"
		case ActorRuleHardPriorTokenRug:
			return "review_verified_previous_token_incident"
		}
	}
	if verdict.Verdict == "compounding_rule" || strings.EqualFold(track.State, "correlated") {
		return "collect_live_transaction_evidence"
	}
	if len(verdict.WatchFlags) > 0 {
		return "verify_inferred_relations"
	}
	if track.VerifiedEvidenceCount > 0 {
		return "review_verified_evidence"
	}
	if track.DominantHolderTokenCount >= 2 {
		return "expand_cross_token_holder_network"
	}
	if track.CreatedTokenCount >= 2 {
		return "expand_creator_token_history"
	}
	return "monitor_sensor_memory"
}

func actorDefenseNeedsLiveEvidence(track ActorDefenseTrack, verdict ActorDefenseRuleVerdict) bool {
	if verdict.Verdict == "hard_trigger" {
		return false
	}
	return verdict.Verdict == "compounding_rule" || strings.EqualFold(track.State, "correlated") || len(verdict.WatchFlags) > 0
}

func actorRuleIDList(items []ActorDefenseRuleHit, tier string) string {
	ids := []string{}
	for _, item := range items {
		if tier != "" && item.Tier != tier {
			continue
		}
		ids = append(ids, item.RuleID)
	}
	ids = actorRuleUniqueStrings(ids)
	if len(ids) == 0 {
		return "rule evidence available"
	}
	return strings.Join(ids, ", ")
}
