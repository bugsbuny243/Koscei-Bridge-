package services

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type ActorDistributionTarget struct {
	CreatorWallet      string    `json:"creator_wallet"`
	Mint               string    `json:"mint"`
	CreationSignature  string    `json:"creation_signature,omitempty"`
	VerificationStatus string    `json:"verification_status"`
	FirstObservedAt    time.Time `json:"first_observed_at"`
	LastObservedAt     time.Time `json:"last_observed_at"`
}

// ResolvePersistentCreatorMint prevents the recipient investigator from
// becoming a general-purpose history crawler. The creator→mint relation must
// already exist in Koschei's persistent actor index.
func (s *ActorDefenseStore) ResolvePersistentCreatorMint(ctx context.Context, creator, mint, network string) (ActorDistributionTarget, error) {
	creator = strings.TrimSpace(creator)
	mint = strings.TrimSpace(mint)
	network = normalizeRadarNetwork(network)
	if s == nil || s.DB == nil {
		return ActorDistributionTarget{}, fmt.Errorf("actor defense database is unavailable")
	}
	if creator == "" || mint == "" {
		return ActorDistributionTarget{}, fmt.Errorf("creator and mint are required")
	}
	var target ActorDistributionTarget
	err := s.DB.QueryRowContext(ctx, `
		SELECT actor_wallet,token_mint,
		       COALESCE((array_agg(NULLIF(btrim(signature),'') ORDER BY last_observed_at DESC)
		           FILTER (WHERE signature IS NOT NULL AND btrim(signature)<>''))[1],''),
		       CASE WHEN bool_or(verification_status='verified') THEN 'verified' ELSE 'observed' END,
		       min(first_observed_at),max(last_observed_at)
		FROM security_actor_evidence
		WHERE network=$3
		  AND actor_wallet=$1
		  AND token_mint=$2
		  AND actor_role='creator_deployer'
		  AND relation='created_token'
		  AND verification_status IN ('verified','observed')
		GROUP BY actor_wallet,token_mint`, creator, mint, network).Scan(
		&target.CreatorWallet, &target.Mint, &target.CreationSignature,
		&target.VerificationStatus, &target.FirstObservedAt, &target.LastObservedAt,
	)
	if err == sql.ErrNoRows {
		return ActorDistributionTarget{}, fmt.Errorf("creator mint relation not found in persistent actor index")
	}
	if err != nil {
		return ActorDistributionTarget{}, err
	}
	return target, nil
}
