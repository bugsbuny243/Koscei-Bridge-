package services

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type RecursiveLineageLifecycleReference struct {
	ActorWallet        string    `json:"actor_wallet"`
	Mint               string    `json:"mint"`
	CreationSignature  string    `json:"creation_signature,omitempty"`
	CreationSlot       int64     `json:"creation_slot,omitempty"`
	FirstObservedAt    time.Time `json:"first_observed_at,omitempty"`
	LastObservedAt     time.Time `json:"last_observed_at,omitempty"`
	FateStatus         string    `json:"fate_status"`
	EvidenceStatus     string    `json:"evidence_status"`
	ReferenceComplete  bool      `json:"reference_complete"`
}

type RecursiveLineageLifecycleReport struct {
	Wallet      string                              `json:"wallet"`
	Network     string                              `json:"network"`
	Complete    bool                                `json:"complete"`
	References  []RecursiveLineageLifecycleReference `json:"references"`
	Limitations []string                            `json:"limitations"`
}

func (s *ActorDefenseStore) LoadBoundedRecursiveLifecycle(ctx context.Context, wallet, network, currentMint string, limit int) (RecursiveLineageLifecycleReport, error) {
	wallet = strings.TrimSpace(wallet)
	network = normalizeRadarNetwork(network)
	currentMint = strings.TrimSpace(currentMint)
	if limit <= 0 || limit > MaxRecursiveLineageTokensPerSeed {
		limit = MaxRecursiveLineageTokensPerSeed
	}
	out := RecursiveLineageLifecycleReport{
		Wallet: wallet, Network: network, Complete: true,
		References: []RecursiveLineageLifecycleReference{}, Limitations: []string{},
	}
	if s == nil || s.DB == nil {
		return out, fmt.Errorf("actor defense database is unavailable")
	}
	if wallet == "" {
		return out, fmt.Errorf("actor wallet is required")
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT mint,COALESCE(creation_signature,''),COALESCE(creation_slot,0),first_observed_at,last_observed_at,fate_status
		FROM security_actor_token_lifecycle
		WHERE network=$2 AND actor_wallet=$1 AND ($3='' OR mint<>$3)
		ORDER BY last_observed_at DESC,mint
		LIMIT $4`, wallet, network, currentMint, limit+1)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		if len(out.References) >= limit {
			out.Complete = false
			continue
		}
		var row RecursiveLineageLifecycleReference
		if err := rows.Scan(&row.Mint, &row.CreationSignature, &row.CreationSlot, &row.FirstObservedAt, &row.LastObservedAt, &row.FateStatus); err != nil {
			return out, err
		}
		row.ActorWallet = wallet
		row.Mint = strings.TrimSpace(row.Mint)
		row.CreationSignature = strings.TrimSpace(row.CreationSignature)
		row.FateStatus = strings.TrimSpace(row.FateStatus)
		row.ReferenceComplete = row.Mint != "" && row.CreationSignature != "" && row.CreationSlot > 0 && !row.FirstObservedAt.IsZero() && !row.LastObservedAt.IsZero()
		if row.ReferenceComplete {
			row.EvidenceStatus = "verified"
		} else {
			row.EvidenceStatus = "observed"
		}
		if row.Mint != "" {
			out.References = append(out.References, row)
		}
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if !out.Complete {
		out.Limitations = append(out.Limitations, "Creator lifecycle references hit the bounded per-wallet token cap.")
	}
	out.Limitations = append(out.Limitations, "Lifecycle fate records active vs inactive/dead observations; fate status alone never classifies a token as rugged.")
	return out, nil
}
