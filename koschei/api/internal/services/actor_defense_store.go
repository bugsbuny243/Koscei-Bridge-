package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ActorDefenseTokenObservation is a wallet-centric token relation assembled
// from Koschei's existing Pump discovery, holder snapshot and trade ledgers.
// Roles are evidence labels, not identity or wrongdoing claims.
type ActorDefenseTokenObservation struct {
	Mint             string    `json:"mint"`
	Name             string    `json:"name,omitempty"`
	Symbol           string    `json:"symbol,omitempty"`
	Roles            []string  `json:"roles"`
	CreatorSignature string    `json:"creator_signature,omitempty"`
	HolderRank       int       `json:"holder_rank,omitempty"`
	HolderPercentage float64   `json:"holder_percentage,omitempty"`
	BuyCount         int64     `json:"buy_count,omitempty"`
	SellCount        int64     `json:"sell_count,omitempty"`
	SOLBought        float64   `json:"sol_bought,omitempty"`
	SOLSold          float64   `json:"sol_sold,omitempty"`
	FirstObservedAt  time.Time `json:"first_observed_at,omitempty"`
	LastObservedAt   time.Time `json:"last_observed_at,omitempty"`
}

type ActorDefenseRelatedActor struct {
	Wallet           string    `json:"wallet"`
	SharedTokenCount int       `json:"shared_token_count"`
	MaxPercentage    float64   `json:"max_holder_percentage"`
	FirstObservedAt  time.Time `json:"first_observed_at,omitempty"`
	LastObservedAt   time.Time `json:"last_observed_at,omitempty"`
}

type ActorDefenseEvidenceRecord struct {
	ID                 string         `json:"id,omitempty"`
	Network            string         `json:"network"`
	ActorWallet        string         `json:"actor_wallet"`
	CounterpartKind    string         `json:"counterpart_kind"`
	CounterpartID      string         `json:"counterpart_id"`
	Relation           string         `json:"relation"`
	VerificationStatus string         `json:"verification_status"`
	EvidenceKey        string         `json:"evidence_key"`
	Source             string         `json:"source"`
	Signature          string         `json:"signature,omitempty"`
	Slot               int64          `json:"slot,omitempty"`
	ObservedAt         time.Time      `json:"observed_at"`
	AmountNative       float64        `json:"amount_native,omitempty"`
	TokenMint          string         `json:"token_mint,omitempty"`
	TokenAmount        float64        `json:"token_amount,omitempty"`
	OccurrenceCount    int64          `json:"occurrence_count"`
	Metadata           map[string]any `json:"metadata"`
}

type ActorDefenseTrack struct {
	ID                       string         `json:"id,omitempty"`
	Network                  string         `json:"network"`
	TargetKind               string         `json:"target_kind"`
	TargetID                 string         `json:"target_id"`
	State                    string         `json:"state"`
	CreatedTokenCount        int            `json:"created_token_count"`
	DominantHolderTokenCount int            `json:"dominant_holder_token_count"`
	TradedTokenCount         int            `json:"traded_token_count"`
	RelatedActorCount        int            `json:"related_actor_count"`
	VerifiedEvidenceCount    int            `json:"verified_evidence_count"`
	ObservedEvidenceCount    int            `json:"observed_evidence_count"`
	Dossier                  map[string]any `json:"dossier"`
	FirstSeenAt              time.Time      `json:"first_seen_at"`
	LastSeenAt               time.Time      `json:"last_seen_at"`
	LastInvestigatedAt       time.Time      `json:"last_investigated_at"`
}

type ActorDefenseDossier struct {
	Wallet        string                         `json:"wallet"`
	Network       string                         `json:"network"`
	Track         ActorDefenseTrack              `json:"track"`
	Tokens        []ActorDefenseTokenObservation `json:"tokens"`
	RelatedActors []ActorDefenseRelatedActor     `json:"related_actors"`
	Evidence      []ActorDefenseEvidenceRecord   `json:"evidence"`
	Coverage      map[string]any                 `json:"coverage"`
	Policy        map[string]any                 `json:"evidence_policy"`
	GeneratedAt   time.Time                      `json:"generated_at"`
}

type ActorDefenseStore struct {
	DB *sql.DB
}

func NewActorDefenseStore(db *sql.DB) *ActorDefenseStore {
	return &ActorDefenseStore{DB: db}
}

type actorDefenseTokenBuilder struct {
	item  ActorDefenseTokenObservation
	roles map[string]bool
}

func (s *ActorDefenseStore) LoadWalletDossier(ctx context.Context, wallet, network string, relationLimit int) (ActorDefenseDossier, error) {
	wallet = strings.TrimSpace(wallet)
	network = normalizeRadarNetwork(network)
	if s == nil || s.DB == nil {
		return ActorDefenseDossier{}, fmt.Errorf("actor defense database is unavailable")
	}
	if wallet == "" {
		return ActorDefenseDossier{}, fmt.Errorf("actor wallet is required")
	}
	if relationLimit <= 0 || relationLimit > 200 {
		relationLimit = 50
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

	createdCount, err := s.loadCreatedTokens(ctx, wallet, network, ensure)
	if err != nil {
		return ActorDefenseDossier{}, err
	}
	dominantCount, err := s.loadDominantHolderTokens(ctx, wallet, network, ensure)
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

	related, err := s.loadRelatedActors(ctx, wallet, network, relationLimit)
	if err != nil {
		return ActorDefenseDossier{}, err
	}
	evidence, err := s.loadEvidence(ctx, wallet, network, relationLimit)
	if err != nil {
		return ActorDefenseDossier{}, err
	}
	verified, observed := 0, 0
	for _, row := range evidence {
		if row.VerificationStatus == "verified" {
			verified++
		} else if row.VerificationStatus == "observed" {
			observed++
		}
	}

	track := ActorDefenseTrack{
		Network: network, TargetKind: "wallet", TargetID: wallet,
		CreatedTokenCount: createdCount, DominantHolderTokenCount: dominantCount,
		TradedTokenCount: tradedCount, RelatedActorCount: len(related),
		VerifiedEvidenceCount: verified, ObservedEvidenceCount: observed,
	}
	track.State = DeriveActorDefenseTrackState(track, related)
	track.Dossier = map[string]any{
		"token_count":                 len(tokens),
		"direct_evidence_count":       len(evidence),
		"state_basis":                 []string{"pump_creator_observations", "owner_resolved_holder_snapshots", "pump_trade_ledger", "signed_transaction_evidence"},
		"no_identity_or_intent_claim": true,
	}
	if err := s.upsertTrack(ctx, &track); err != nil {
		return ActorDefenseDossier{}, err
	}

	return ActorDefenseDossier{
		Wallet: wallet, Network: network, Track: track, Tokens: tokens,
		RelatedActors: related, Evidence: evidence,
		Coverage: map[string]any{
			"created_tokens":            createdCount,
			"dominant_holder_tokens":    dominantCount,
			"traded_tokens":             tradedCount,
			"related_actors":            len(related),
			"persisted_direct_evidence": len(evidence),
		},
		Policy: map[string]any{
			"no_evidence_no_claim":                                           true,
			"wallet_addresses_are_case_sensitive":                            true,
			"verified_requires_transaction_or_owner_resolved_chain_evidence": true,
			"identity_or_wrongdoing_claim":                                   false,
		},
		GeneratedAt: time.Now().UTC(),
	}, nil
}

func (s *ActorDefenseStore) loadCreatedTokens(ctx context.Context, wallet, network string, ensure func(string) *actorDefenseTokenBuilder) (int, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT target,
		       max(COALESCE(NULLIF(signals->>'token_name',''),NULLIF(raw_summary->>'name',''),'')),
		       max(COALESCE(NULLIF(signals->>'token_symbol',''),NULLIF(raw_summary->>'symbol',''),'')),
		       min(created_at), max(created_at), max(COALESCE(signature,'')), count(*)
		FROM security_radar_events
		WHERE network=$2 AND btrim(target)<>'' AND (
			COALESCE(signals->>'creator_wallet','')=$1 OR
			COALESCE(signals->>'deployer_wallet','')=$1 OR
			(source_address=$1 AND source='pumpportal')
		)
		GROUP BY target
		ORDER BY max(created_at) DESC`, wallet, network)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var mint, name, symbol, signature string
		var firstAt, lastAt time.Time
		var observations int64
		if err := rows.Scan(&mint, &name, &symbol, &firstAt, &lastAt, &signature, &observations); err != nil {
			return 0, err
		}
		row := ensure(mint)
		row.roles["creator_deployer"] = true
		row.item.Name, row.item.Symbol = strings.TrimSpace(name), strings.TrimSpace(symbol)
		row.item.CreatorSignature = strings.TrimSpace(signature)
		mergeActorDefenseTimes(&row.item, firstAt, lastAt)
		count++
	}
	return count, rows.Err()
}

func (s *ActorDefenseStore) loadDominantHolderTokens(ctx context.Context, wallet, network string, ensure func(string) *actorDefenseTokenBuilder) (int, error) {
	rows, err := s.DB.QueryContext(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (target) target,holder_rank,percentage,scanned_at
			FROM security_radar_holder_snapshots
			WHERE owner_wallet=$1 AND network=$2
			ORDER BY target,scanned_at DESC,id DESC
		)
		SELECT target,holder_rank,percentage::double precision,scanned_at
		FROM latest
		ORDER BY scanned_at DESC`, wallet, network)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var mint string
		var rank int
		var percentage float64
		var observed time.Time
		if err := rows.Scan(&mint, &rank, &percentage, &observed); err != nil {
			return 0, err
		}
		row := ensure(mint)
		row.roles["dominant_holder"] = true
		row.item.HolderRank = rank
		row.item.HolderPercentage = percentage
		mergeActorDefenseTimes(&row.item, observed, observed)
		count++
	}
	return count, rows.Err()
}

func (s *ActorDefenseStore) loadTradedTokens(ctx context.Context, wallet string, ensure func(string) *actorDefenseTokenBuilder) (int, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT mint,
		       count(*) FILTER (WHERE side='buy'),
		       count(*) FILTER (WHERE side='sell'),
		       COALESCE(sum(sol_amount) FILTER (WHERE side='buy'),0)::double precision,
		       COALESCE(sum(sol_amount) FILTER (WHERE side='sell'),0)::double precision,
		       min(COALESCE(block_time,created_at)),max(COALESCE(block_time,created_at))
		FROM token_trade_events
		WHERE trader=$1 AND btrim(mint)<>''
		GROUP BY mint
		ORDER BY max(COALESCE(block_time,created_at)) DESC
		LIMIT 500`, wallet)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var mint string
		var buys, sells int64
		var solBought, solSold float64
		var firstAt, lastAt time.Time
		if err := rows.Scan(&mint, &buys, &sells, &solBought, &solSold, &firstAt, &lastAt); err != nil {
			return 0, err
		}
		row := ensure(mint)
		row.roles["pump_trader"] = true
		row.item.BuyCount, row.item.SellCount = buys, sells
		row.item.SOLBought, row.item.SOLSold = solBought, solSold
		mergeActorDefenseTimes(&row.item, firstAt, lastAt)
		count++
	}
	return count, rows.Err()
}

func (s *ActorDefenseStore) loadRelatedActors(ctx context.Context, wallet, network string, limit int) ([]ActorDefenseRelatedActor, error) {
	rows, err := s.DB.QueryContext(ctx, `
		WITH actor_tokens AS (
			SELECT DISTINCT target
			FROM security_radar_events
			WHERE network=$2 AND btrim(target)<>'' AND (
				COALESCE(signals->>'creator_wallet','')=$1 OR
				COALESCE(signals->>'deployer_wallet','')=$1 OR
				(source_address=$1 AND source='pumpportal')
			)
			UNION
			SELECT DISTINCT target
			FROM security_radar_holder_snapshots
			WHERE network=$2 AND owner_wallet=$1
		), latest AS (
			SELECT DISTINCT ON (target,owner_wallet)
				target,owner_wallet,percentage,scanned_at
			FROM security_radar_holder_snapshots
			WHERE network=$2
			ORDER BY target,owner_wallet,scanned_at DESC,id DESC
		)
		SELECT l.owner_wallet,count(DISTINCT l.target),max(l.percentage)::double precision,
		       min(l.scanned_at),max(l.scanned_at)
		FROM latest l
		JOIN actor_tokens t ON t.target=l.target
		WHERE l.owner_wallet<>$1 AND btrim(l.owner_wallet)<>''
		GROUP BY l.owner_wallet
		ORDER BY count(DISTINCT l.target) DESC,max(l.percentage) DESC,max(l.scanned_at) DESC
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

func (s *ActorDefenseStore) loadEvidence(ctx context.Context, wallet, network string, limit int) ([]ActorDefenseEvidenceRecord, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id::text,network,actor_wallet,counterpart_kind,counterpart_id,relation,
		       verification_status,evidence_key,source,COALESCE(signature,''),COALESCE(slot,0),
		       observed_at,amount_native::double precision,COALESCE(token_mint,''),
		       token_amount::double precision,occurrence_count,metadata
		FROM security_actor_evidence
		WHERE network=$2 AND (actor_wallet=$1 OR (counterpart_kind='wallet' AND counterpart_id=$1))
		ORDER BY CASE verification_status WHEN 'verified' THEN 0 WHEN 'observed' THEN 1 ELSE 2 END,
		         observed_at DESC,id DESC
		LIMIT $3`, wallet, network, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ActorDefenseEvidenceRecord{}
	for rows.Next() {
		var item ActorDefenseEvidenceRecord
		var metadataRaw []byte
		if err := rows.Scan(&item.ID, &item.Network, &item.ActorWallet, &item.CounterpartKind, &item.CounterpartID,
			&item.Relation, &item.VerificationStatus, &item.EvidenceKey, &item.Source, &item.Signature,
			&item.Slot, &item.ObservedAt, &item.AmountNative, &item.TokenMint, &item.TokenAmount,
			&item.OccurrenceCount, &metadataRaw); err != nil {
			return nil, err
		}
		item.Metadata = map[string]any{}
		_ = json.Unmarshal(metadataRaw, &item.Metadata)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *ActorDefenseStore) UpsertEvidence(ctx context.Context, item ActorDefenseEvidenceRecord) error {
	if s == nil || s.DB == nil {
		return fmt.Errorf("actor defense database is unavailable")
	}
	item.Network = normalizeRadarNetwork(item.Network)
	item.ActorWallet = strings.TrimSpace(item.ActorWallet)
	item.CounterpartKind = strings.TrimSpace(item.CounterpartKind)
	item.CounterpartID = strings.TrimSpace(item.CounterpartID)
	item.Relation = strings.TrimSpace(item.Relation)
	item.EvidenceKey = strings.TrimSpace(item.EvidenceKey)
	item.Source = strings.TrimSpace(item.Source)
	item.Signature = strings.TrimSpace(item.Signature)
	item.TokenMint = strings.TrimSpace(item.TokenMint)
	item.VerificationStatus = normalizeActorEvidenceStatus(item.VerificationStatus)
	if item.Source == "" {
		item.Source = "solana_rpc"
	}
	if item.ObservedAt.IsZero() {
		item.ObservedAt = time.Now().UTC()
	}
	if item.ActorWallet == "" || item.CounterpartKind == "" || item.CounterpartID == "" || item.Relation == "" || item.EvidenceKey == "" {
		return fmt.Errorf("actor evidence is incomplete")
	}
	metadata, err := json.Marshal(nonNilMap(item.Metadata))
	if err != nil {
		return fmt.Errorf("encode actor evidence metadata: %w", err)
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO security_actor_evidence
			(network,actor_wallet,counterpart_kind,counterpart_id,relation,verification_status,
			 evidence_key,source,signature,slot,observed_at,amount_native,token_mint,token_amount,
			 occurrence_count,metadata,created_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),NULLIF($10,0),$11,$12,NULLIF($13,''),$14,1,$15::jsonb,now(),now())
		ON CONFLICT (network,actor_wallet,counterpart_kind,counterpart_id,relation,source,evidence_key)
		DO UPDATE SET
			verification_status=CASE
				WHEN security_actor_evidence.verification_status='verified' THEN 'verified'
				ELSE EXCLUDED.verification_status
			END,
			signature=COALESCE(EXCLUDED.signature,security_actor_evidence.signature),
			slot=COALESCE(EXCLUDED.slot,security_actor_evidence.slot),
			observed_at=GREATEST(security_actor_evidence.observed_at,EXCLUDED.observed_at),
			amount_native=GREATEST(security_actor_evidence.amount_native,EXCLUDED.amount_native),
			token_mint=COALESCE(EXCLUDED.token_mint,security_actor_evidence.token_mint),
			token_amount=GREATEST(security_actor_evidence.token_amount,EXCLUDED.token_amount),
			occurrence_count=security_actor_evidence.occurrence_count+1,
			metadata=security_actor_evidence.metadata || EXCLUDED.metadata,
			updated_at=now()`,
		item.Network, item.ActorWallet, item.CounterpartKind, item.CounterpartID, item.Relation,
		item.VerificationStatus, item.EvidenceKey, item.Source, item.Signature, item.Slot,
		item.ObservedAt.UTC(), item.AmountNative, item.TokenMint, item.TokenAmount, string(metadata))
	if err != nil {
		return err
	}
	if event, ok := actorExitEventFromEvidence(item); ok {
		if err := upsertActorExitEventTx(ctx, tx, event); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *ActorDefenseStore) upsertTrack(ctx context.Context, track *ActorDefenseTrack) error {
	if track == nil {
		return fmt.Errorf("actor defense track is required")
	}
	var existingState string
	err := s.DB.QueryRowContext(ctx, `
		SELECT state FROM security_threat_tracks
		WHERE network=$1 AND target_kind=$2 AND target_id=$3`, track.Network, track.TargetKind, track.TargetID).Scan(&existingState)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if actorDefenseStateRank(existingState) > actorDefenseStateRank(track.State) {
		track.State = existingState
	}
	dossier, err := json.Marshal(nonNilMap(track.Dossier))
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	return s.DB.QueryRowContext(ctx, `
		INSERT INTO security_threat_tracks
			(network,target_kind,target_id,state,created_token_count,dominant_holder_token_count,
			 traded_token_count,related_actor_count,verified_evidence_count,observed_evidence_count,
			 dossier,first_seen_at,last_seen_at,last_investigated_at,created_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$12,$12,now(),now())
		ON CONFLICT (network,target_kind,target_id)
		DO UPDATE SET
			state=EXCLUDED.state,
			created_token_count=EXCLUDED.created_token_count,
			dominant_holder_token_count=EXCLUDED.dominant_holder_token_count,
			traded_token_count=EXCLUDED.traded_token_count,
			related_actor_count=EXCLUDED.related_actor_count,
			verified_evidence_count=EXCLUDED.verified_evidence_count,
			observed_evidence_count=EXCLUDED.observed_evidence_count,
			dossier=EXCLUDED.dossier,
			last_seen_at=EXCLUDED.last_seen_at,
			last_investigated_at=EXCLUDED.last_investigated_at,
			updated_at=now()
		RETURNING id::text,first_seen_at,last_seen_at,last_investigated_at`,
		track.Network, track.TargetKind, track.TargetID, track.State, track.CreatedTokenCount,
		track.DominantHolderTokenCount, track.TradedTokenCount, track.RelatedActorCount,
		track.VerifiedEvidenceCount, track.ObservedEvidenceCount, string(dossier), now).Scan(
		&track.ID, &track.FirstSeenAt, &track.LastSeenAt, &track.LastInvestigatedAt)
}

func DeriveActorDefenseTrackState(track ActorDefenseTrack, related []ActorDefenseRelatedActor) string {
	state := "detected"
	tokenCount := track.CreatedTokenCount + track.DominantHolderTokenCount + track.TradedTokenCount
	if tokenCount >= 2 || track.RelatedActorCount > 0 || track.ObservedEvidenceCount > 0 || track.VerifiedEvidenceCount > 0 {
		state = "tracked"
	}
	sharedAcrossTokens := false
	for _, item := range related {
		if item.SharedTokenCount >= 2 {
			sharedAcrossTokens = true
			break
		}
	}
	if sharedAcrossTokens || (track.CreatedTokenCount >= 2 && track.RelatedActorCount > 0) || track.RelatedActorCount >= 3 {
		state = "correlated"
	}
	if track.VerifiedEvidenceCount > 0 {
		state = "verified"
	}
	return state
}

func normalizeActorEvidenceStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "verified":
		return "verified"
	case "inferred":
		return "inferred"
	case "unverified":
		return "unverified"
	default:
		return "observed"
	}
}

func actorDefenseStateRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "alerted":
		return 5
	case "verified":
		return 4
	case "correlated":
		return 3
	case "tracked":
		return 2
	case "detected":
		return 1
	default:
		return 0
	}
}

func mergeActorDefenseTimes(item *ActorDefenseTokenObservation, firstAt, lastAt time.Time) {
	if item == nil {
		return
	}
	firstAt, lastAt = firstAt.UTC(), lastAt.UTC()
	if item.FirstObservedAt.IsZero() || (!firstAt.IsZero() && firstAt.Before(item.FirstObservedAt)) {
		item.FirstObservedAt = firstAt
	}
	if lastAt.After(item.LastObservedAt) {
		item.LastObservedAt = lastAt
	}
}
