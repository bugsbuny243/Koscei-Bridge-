package services

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestPersistentFundingClusterOutcomesPostgres17(t *testing.T) {
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

	nonce := time.Now().UTC().UnixNano()
	network := "solana-mainnet"
	funder := fmt.Sprintf("OutcomeFunder%d", nonce)
	creatorA := fmt.Sprintf("OutcomeCreatorA%d", nonce)
	creatorB := fmt.Sprintf("OutcomeCreatorB%d", nonce)
	tokenA := fmt.Sprintf("OutcomeTokenA%d", nonce)
	tokenB := fmt.Sprintf("OutcomeTokenB%d", nonce)
	tokenC := fmt.Sprintf("OutcomeTokenC%d", nonce)
	baseTime := time.Now().UTC().Add(-48 * time.Hour)

	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM security_actor_exit_events WHERE network=$1 AND actor_wallet IN ($2,$3)`, network, creatorA, creatorB)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM security_unified_radar_verdicts WHERE network=$1 AND target_id IN ($2,$3,$4)`, network, tokenA, tokenB, tokenC)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM security_actor_token_lifecycle WHERE network=$1 AND actor_wallet IN ($2,$3)`, network, creatorA, creatorB)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM security_actor_evidence WHERE network=$1 AND (actor_wallet IN ($2,$3) OR counterpart_id=$4)`, network, creatorA, creatorB, funder)
	}()

	store := NewActorDefenseStore(db)
	put := func(item ActorDefenseEvidenceRecord) {
		t.Helper()
		if err := store.UpsertEvidence(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	funding := func(wallet, signature, status string, slot int64, observedAt time.Time) ActorDefenseEvidenceRecord {
		return ActorDefenseEvidenceRecord{
			Network: network, ActorWallet: wallet,
			CounterpartKind: "wallet", CounterpartID: funder,
			Relation: "initial_funding_in", VerificationStatus: status,
			EvidenceKey: signature + ":initial_funding", Source: "funding_cluster_outcome_test",
			Signature: signature, Slot: slot, ObservedAt: observedAt,
			Metadata: map[string]any{
				"actor_role": "funded_wallet", "source_wallet": funder,
				"destination_wallet": wallet, "history_complete": true,
			},
		}
	}
	put(funding(creatorA, fmt.Sprintf("fund-a-%d", nonce), "verified", 1001, baseTime))
	put(funding(creatorB, fmt.Sprintf("fund-b-%d", nonce), "observed", 1002, baseTime.Add(time.Hour)))

	created := func(wallet, mint, status string, index int) ActorDefenseEvidenceRecord {
		return ActorDefenseEvidenceRecord{
			Network: network, ActorWallet: wallet,
			CounterpartKind: "token", CounterpartID: mint, TokenMint: mint,
			Relation: "created_token", VerificationStatus: status,
			EvidenceKey: fmt.Sprintf("created-%d-%d", nonce, index), Source: "funding_cluster_outcome_test",
			ObservedAt: baseTime.Add(time.Duration(index+2) * time.Hour),
			Metadata: map[string]any{"actor_role": "creator_deployer", "persistent_actor_index": true},
		}
	}
	put(created(creatorA, tokenA, "verified", 1))
	put(created(creatorA, tokenB, "observed", 2))
	put(created(creatorB, tokenC, "observed", 3))

	_, err = db.ExecContext(ctx, `
		INSERT INTO security_actor_token_lifecycle
		(network,actor_wallet,mint,first_observed_at,last_observed_at,first_liquid_observed_at,last_liquid_observed_at,current_liquidity_usd,current_price_usd,fate_status,observation_count)
		VALUES
		($1,$2,$3,$4,$5,$4,$5,25000,0.25,'active',4),
		($1,$2,$6,$4,$7,$4,$5,0,0,'inactive_or_dead',6),
		($1,$8,$9,$4,$5,$4,$5,18000,0.18,'active',3)`,
		network, creatorA, tokenA, baseTime.Add(4*time.Hour), baseTime.Add(20*time.Hour), tokenB, baseTime.Add(30*time.Hour), creatorB, tokenC)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `
		UPDATE security_actor_token_lifecycle
		SET first_inactive_observed_at=$4,current_inactive_since=$4
		WHERE network=$1 AND actor_wallet=$2 AND mint=$3`, network, creatorA, tokenB, baseTime.Add(28*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO security_unified_radar_verdicts
		(network,target_kind,target_id,grade,verdict,ruleset_version,actor_ruleset_version,signed,signature,fingerprint,first_seen_at,last_seen_at)
		VALUES
		($1,'token',$2,'B','compounding_rule','rules-v1','actor-rules-v1',true,$3,$4,$5,$5),
		($1,'token',$6,'-','watch_only','rules-v1','actor-rules-v1',false,NULL,$7,$5,$5)`,
		network, tokenB, fmt.Sprintf("signed-verdict-%d", nonce), fmt.Sprintf("fingerprint-signed-%d", nonce), baseTime.Add(32*time.Hour), tokenC, fmt.Sprintf("fingerprint-unsigned-%d", nonce))
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO security_actor_exit_events
		(actor_wallet,network,target,event_kind,evidence_state,signature,slot,observed_at,source_rule_id,detail)
		VALUES
		($1,$2,$3,'creator_sell','observed',$4,2001,$5,'TEST-CREATOR-SELL','{}'::jsonb),
		($1,$2,$3,'liquidity_removal','verified',$6,2002,$7,'TEST-LIQUIDITY-REMOVE','{}'::jsonb)`,
		creatorA, network, tokenB, fmt.Sprintf("exit-observed-%d", nonce), baseTime.Add(29*time.Hour), fmt.Sprintf("exit-verified-%d", nonce), baseTime.Add(31*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	report, err := LoadPersistentFundingClusterOutcomes(ctx, db, creatorA, network, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Available || !report.Complete || report.Status != "persistent_token_outcomes_observed" {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.FundingSourceCount != 1 || report.FundedActorCount != 2 || report.TokenCount != 3 {
		t.Fatalf("unexpected coverage counts: %+v", report)
	}
	if report.LifecycleCoveredTokenCount != 3 || report.InactiveOrDeadTokenCount != 1 || report.VerifiedLifecycleTransitions != 1 {
		t.Fatalf("unexpected lifecycle counts: %+v", report)
	}
	if report.SignedVerdictTokenCount != 1 || report.ExitEvidenceTokenCount != 1 || report.VerifiedExitEventCount != 1 {
		t.Fatalf("unexpected verdict/exit counts: %+v", report)
	}
	if report.VerdictAuthority || report.SameOperatorClaim || report.RealWorldIdentityClaim || report.RugClaim || report.WrongdoingClaim {
		t.Fatalf("outcome memory acquired prohibited authority: %+v", report)
	}

	var tokenBOutcome *PersistentFundingTokenOutcome
	for i := range report.Outcomes {
		if report.Outcomes[i].Mint == tokenB {
			tokenBOutcome = &report.Outcomes[i]
			break
		}
	}
	if tokenBOutcome == nil {
		t.Fatalf("token B outcome missing: %+v", report.Outcomes)
	}
	if tokenBOutcome.CreationEvidenceStatus != "observed" || tokenBOutcome.LifecycleFateStatus != ActorTokenFateInactiveOrDead || !tokenBOutcome.VerifiedLifecycleTransition {
		t.Fatalf("unexpected token B lifecycle: %+v", tokenBOutcome)
	}
	if !tokenBOutcome.SignedVerdictAvailable || tokenBOutcome.LatestSignedGrade != "B" || tokenBOutcome.LatestSignedVerdict != "compounding_rule" {
		t.Fatalf("unexpected token B signed verdict: %+v", tokenBOutcome)
	}
	if tokenBOutcome.ExitEventCount != 2 || tokenBOutcome.VerifiedExitEventCount != 1 || tokenBOutcome.ObservedExitEventCount != 1 {
		t.Fatalf("unexpected token B exit evidence: %+v", tokenBOutcome)
	}
	if len(tokenBOutcome.ExitEventKinds) != 2 || tokenBOutcome.ExitEventKinds[0] != "creator_sell" || tokenBOutcome.ExitEventKinds[1] != "liquidity_removal" {
		t.Fatalf("unexpected exit kinds: %+v", tokenBOutcome.ExitEventKinds)
	}

	funderReport, err := LoadPersistentFundingClusterOutcomes(ctx, db, funder, network, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !funderReport.Available || funderReport.FundingSourceCount != 1 || funderReport.TokenCount != 3 {
		t.Fatalf("funder-centric outcome history missing: %+v", funderReport)
	}
}
