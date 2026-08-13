package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"koschei/api/internal/services"
)

func TestLiquidityMovementActorEvidencePostgres17(t *testing.T) {
	databaseURL := os.Getenv("KOSCHEI_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KOSCHEI_TEST_DATABASE_URL is not set")
	}
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	suffix := time.Now().UTC().Format("20060102150405.000000000")
	target := "ci-liquidity-token-" + suffix
	creator := "ci-liquidity-creator-" + suffix
	unrelated := "ci-liquidity-unrelated-" + suffix
	pool := "ci-liquidity-pool-" + suffix
	program := "ci-liquidity-program-" + suffix
	network := "solana-mainnet"
	observedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)

	store := services.NewSecurityRadarStore(db)
	verdictID, err := store.InsertVerdict(ctx, services.SecurityRadarVerdictRecord{
		ModuleID:       services.ModuleFinalVerdictEngine,
		Target:         target,
		TargetType:     "token",
		Network:        network,
		Grade:          "F",
		RiskIndex:      91,
		RiskLevel:      "critical",
		Verdict:        "CI material verdict for verified liquidity incident projection.",
		Recommendation: "CI only",
		Evidence:       []string{"verified on-chain CI evidence"},
		Signals: map[string]any{
			"verified_evidence":     true,
			"real_onchain_evidence": true,
		},
		RuleVersion: "ci-liquidity-incident-v1",
		Signed:      true,
		Signature:   "ci-verdict-signature-" + suffix,
		Source:      "solana_rpc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if verdictID == "" {
		t.Fatal("expected signed material verdict to persist")
	}

	h := &Handler{DB: db}
	lp := services.LPControlEvidence{
		TokenMint:     target,
		PoolAddress:   pool,
		PoolProgram:   program,
		CreatorWallet: creator,
		ObservedAt:    observedAt,
		LiquidityMovements: []services.LiquidityMovementEvidence{
			{
				Kind:               "remove_liquidity",
				Signature:          "ci-liquidity-remove-" + suffix,
				Slot:               987654321,
				BlockTime:          observedAt.Format(time.RFC3339),
				ActorWallet:        creator,
				PoolAddress:        pool,
				Program:            program,
				SourceWallet:       pool,
				DestinationWallet:  creator,
				TokenDelta:         -2500,
				QuoteDelta:         -12.5,
				CreatorRelated:     true,
				CreatorRelation:    "verified_investigated_creator_signer",
				InstructionTypes:   []string{"withdraw"},
				Source:             "solana_rpc",
				VerificationStatus: "VERIFIED",
				EvidenceKey:        "ci-liquidity-evidence-" + suffix,
			},
		},
	}
	if got := h.persistLiquidityMovementActorEvidence(ctx, network, target, lp); got != 1 {
		t.Fatalf("persisted liquidity actor rows=%d, want 1", got)
	}

	var evidenceCount int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*)
		FROM security_actor_evidence
		WHERE network=$1 AND actor_wallet=$2 AND token_mint=$3
		  AND relation='liquidity_remove_activity'
		  AND verification_status='verified'
		  AND signature=$4 AND slot=$5`,
		network, creator, target, lp.LiquidityMovements[0].Signature, lp.LiquidityMovements[0].Slot).Scan(&evidenceCount); err != nil {
		t.Fatal(err)
	}
	if evidenceCount != 1 {
		t.Fatalf("verified actor evidence rows=%d, want 1", evidenceCount)
	}

	var eventKind, evidenceState, sourceRuleID string
	if err := db.QueryRowContext(ctx, `
		SELECT event_kind,evidence_state,source_rule_id
		FROM security_actor_exit_events
		WHERE network=$1 AND actor_wallet=$2 AND target=$3 AND signature=$4
		ORDER BY observed_at DESC,slot DESC
		LIMIT 1`, network, creator, target, lp.LiquidityMovements[0].Signature).Scan(&eventKind, &evidenceState, &sourceRuleID); err != nil {
		t.Fatal(err)
	}
	if eventKind != services.ActorExitEventLiquidityRemoval || evidenceState != "verified" || sourceRuleID != services.ActorRuleHardCreatorLiquidityRemoval {
		t.Fatalf("unexpected exit event: kind=%q state=%q rule=%q", eventKind, evidenceState, sourceRuleID)
	}

	var incidentEventKind, incidentRiskLevel, incidentSource, incidentEventSignature string
	if err := db.QueryRowContext(ctx, `
		SELECT event_kind,risk_level,verdict_source,event_signature
		FROM security_incident_corpus
		WHERE network=$1 AND actor_wallet=$2 AND target=$3
		ORDER BY created_at DESC
		LIMIT 1`, network, creator, target).Scan(&incidentEventKind, &incidentRiskLevel, &incidentSource, &incidentEventSignature); err != nil {
		t.Fatal(fmt.Errorf("verified liquidity exit did not materialize incident corpus: %w", err))
	}
	if incidentEventKind != services.ActorExitEventLiquidityRemoval || incidentRiskLevel != "critical" || incidentSource != "solana_rpc" || incidentEventSignature != lp.LiquidityMovements[0].Signature {
		t.Fatalf("unexpected incident corpus row: kind=%q risk=%q source=%q sig=%q", incidentEventKind, incidentRiskLevel, incidentSource, incidentEventSignature)
	}

	nonCreatorLP := lp
	nonCreatorLP.LiquidityMovements = []services.LiquidityMovementEvidence{
		{
			Kind:               "remove_liquidity",
			Signature:          "ci-liquidity-unrelated-" + suffix,
			Slot:               987654322,
			BlockTime:          observedAt.Format(time.RFC3339),
			ActorWallet:        unrelated,
			PoolAddress:        pool,
			Program:            program,
			SourceWallet:       pool,
			DestinationWallet:  unrelated,
			TokenDelta:         -100,
			QuoteDelta:         -1,
			CreatorRelated:     false,
			CreatorRelation:    "not_observed",
			InstructionTypes:   []string{"withdraw"},
			Source:             "solana_rpc",
			VerificationStatus: "VERIFIED",
			EvidenceKey:        "ci-liquidity-unrelated-evidence-" + suffix,
		},
	}
	if got := h.persistLiquidityMovementActorEvidence(ctx, network, target, nonCreatorLP); got != 1 {
		t.Fatalf("non-creator evidence persistence=%d, want 1", got)
	}
	var unrelatedExitCount int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM security_actor_exit_events
		WHERE network=$1 AND actor_wallet=$2 AND target=$3`, network, unrelated, target).Scan(&unrelatedExitCount); err != nil {
		t.Fatal(err)
	}
	if unrelatedExitCount != 0 {
		t.Fatalf("non-creator liquidity signer must not become verified exit actor, rows=%d", unrelatedExitCount)
	}
	var unrelatedIncidentCount int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM security_incident_corpus
		WHERE network=$1 AND actor_wallet=$2 AND target=$3`, network, unrelated, target).Scan(&unrelatedIncidentCount); err != nil {
		t.Fatal(err)
	}
	if unrelatedIncidentCount != 0 {
		t.Fatalf("non-creator signer must not enter incident corpus, rows=%d", unrelatedIncidentCount)
	}
}
