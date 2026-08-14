package services

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

type RecursiveLineagePersistentTokenHistory struct {
	Wallet            string                         `json:"wallet"`
	Network           string                         `json:"network"`
	Tokens            []ActorDefenseTokenObservation `json:"tokens"`
	Complete          bool                           `json:"complete"`
	EvidenceRowsRead  int                            `json:"evidence_rows_read"`
	TradeGroupsRead   int                            `json:"trade_groups_read"`
	Limitations       []string                       `json:"limitations"`
}

func (s *ActorDefenseStore) LoadBoundedRecursiveTokenHistory(ctx context.Context, wallet, network string, limit int) (RecursiveLineagePersistentTokenHistory, error) {
	wallet = strings.TrimSpace(wallet)
	network = normalizeRadarNetwork(network)
	if limit <= 0 || limit > MaxRecursiveLineageTokensPerSeed {
		limit = MaxRecursiveLineageTokensPerSeed
	}
	out := RecursiveLineagePersistentTokenHistory{
		Wallet: wallet, Network: network, Tokens: []ActorDefenseTokenObservation{}, Complete: true, Limitations: []string{},
	}
	if s == nil || s.DB == nil {
		return out, fmt.Errorf("actor defense database is unavailable")
	}
	if wallet == "" {
		return out, fmt.Errorf("actor wallet is required")
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

	evidenceCap := limit * 4
	rows, err := s.DB.QueryContext(ctx, `
		SELECT token_mint,actor_role,relation,verification_status,COALESCE(signature,''),first_observed_at,last_observed_at
		FROM security_actor_evidence
		WHERE network=$2
		  AND actor_wallet=$1
		  AND token_mint IS NOT NULL
		  AND btrim(token_mint)<>''
		  AND relation IN ('created_token','dominant_holder_of')
		  AND verification_status IN ('verified','observed')
		ORDER BY last_observed_at DESC,id DESC
		LIMIT $3`, wallet, network, evidenceCap+1)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		out.EvidenceRowsRead++
		if out.EvidenceRowsRead > evidenceCap {
			out.Complete = false
			continue
		}
		var mint, actorRole, relation, status, signature string
		var firstAt, lastAt time.Time
		if err := rows.Scan(&mint, &actorRole, &relation, &status, &signature, &firstAt, &lastAt); err != nil {
			rows.Close()
			return out, err
		}
		mint = strings.TrimSpace(mint)
		if mint == "" {
			continue
		}
		row := ensure(mint)
		switch strings.TrimSpace(relation) {
		case "created_token":
			row.roles["creator_deployer"] = true
			if strings.TrimSpace(signature) != "" {
				row.item.CreatorSignature = strings.TrimSpace(signature)
			}
		case "dominant_holder_of":
			row.roles["dominant_holder"] = true
		default:
			continue
		}
		_ = actorRole
		_ = status
		mergeActorDefenseTimes(&row.item, firstAt, lastAt)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return out, err
	}
	rows.Close()
	if out.EvidenceRowsRead > evidenceCap {
		out.Limitations = append(out.Limitations, "Persistent actor-evidence input hit the bounded per-wallet row cap.")
	}

	tradeCap := limit * 2
	tradeRows, err := s.DB.QueryContext(ctx, `
		SELECT mint,
		       count(*) FILTER (WHERE side='buy'),
		       count(*) FILTER (WHERE side='sell'),
		       COALESCE(sum(sol_amount) FILTER (WHERE side='buy'),0)::double precision,
		       COALESCE(sum(sol_amount) FILTER (WHERE side='sell'),0)::double precision,
		       min(COALESCE(block_time,created_at)),max(COALESCE(block_time,created_at))
		FROM token_trade_events
		WHERE trader=$1 AND btrim(mint)<>''
		GROUP BY mint
		ORDER BY max(COALESCE(block_time,created_at)) DESC,mint
		LIMIT $2`, wallet, tradeCap+1)
	if err != nil {
		return out, err
	}
	for tradeRows.Next() {
		out.TradeGroupsRead++
		if out.TradeGroupsRead > tradeCap {
			out.Complete = false
			continue
		}
		var mint string
		var buys, sells int64
		var solBought, solSold float64
		var firstAt, lastAt time.Time
		if err := tradeRows.Scan(&mint, &buys, &sells, &solBought, &solSold, &firstAt, &lastAt); err != nil {
			tradeRows.Close()
			return out, err
		}
		mint = strings.TrimSpace(mint)
		if mint == "" {
			continue
		}
		row := ensure(mint)
		row.roles["trader"] = true
		row.item.BuyCount += buys
		row.item.SellCount += sells
		row.item.SOLBought += solBought
		row.item.SOLSold += solSold
		mergeActorDefenseTimes(&row.item, firstAt, lastAt)
	}
	if err := tradeRows.Err(); err != nil {
		tradeRows.Close()
		return out, err
	}
	tradeRows.Close()
	if out.TradeGroupsRead > tradeCap {
		out.Limitations = append(out.Limitations, "Persistent trade-history input hit the bounded per-wallet group cap.")
	}

	for _, builder := range builders {
		for role := range builder.roles {
			builder.item.Roles = append(builder.item.Roles, role)
		}
		sort.Strings(builder.item.Roles)
		out.Tokens = append(out.Tokens, builder.item)
	}
	sort.SliceStable(out.Tokens, func(i, j int) bool {
		if !out.Tokens[i].LastObservedAt.Equal(out.Tokens[j].LastObservedAt) {
			return out.Tokens[i].LastObservedAt.After(out.Tokens[j].LastObservedAt)
		}
		return out.Tokens[i].Mint < out.Tokens[j].Mint
	})
	if len(out.Tokens) > limit {
		out.Tokens = out.Tokens[:limit]
		out.Complete = false
		out.Limitations = append(out.Limitations, "Historical token output hit the per-wallet 20-token cap.")
	}
	return out, nil
}
