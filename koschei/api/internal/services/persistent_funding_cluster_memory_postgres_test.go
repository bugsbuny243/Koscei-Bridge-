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

func TestPersistentFundingClusterMemoryPostgres17(t *testing.T) {
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
	funder := fmt.Sprintf("FundingMemoryFunder%d", nonce)
	creatorA := fmt.Sprintf("FundingMemoryCreatorA%d", nonce)
	creatorB := fmt.Sprintf("FundingMemoryCreatorB%d", nonce)
	tokenA := fmt.Sprintf("FundingMemoryTokenA%d", nonce)
	tokenB := fmt.Sprintf("FundingMemoryTokenB%d", nonce)
	tokenC := fmt.Sprintf("FundingMemoryTokenC%d", nonce)
	wallets := []string{funder, creatorA, creatorB}
	defer func() {
		for _, wallet := range wallets {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM security_actor_evidence WHERE network=$1 AND (actor_wallet=$2 OR counterpart_id=$2)`, network, wallet)
			_, _ = db.ExecContext(context.Background(), `DELETE FROM security_threat_tracks WHERE network=$1 AND target_kind='wallet' AND target_id=$2`, network, wallet)
		}
	}()

	store := NewActorDefenseStore(db)
	baseTime := time.Now().UTC().Add(-24 * time.Hour)
	put := func(item ActorDefenseEvidenceRecord) {
		t.Helper()
		if err := store.UpsertEvidence(ctx, item); err != nil {
			t.Fatal(err)
		}
	}

	fundingEvidence := func(wallet, signature string, slot int64, status string, observedAt time.Time) ActorDefenseEvidenceRecord {
		return ActorDefenseEvidenceRecord{
			Network: network, ActorWallet: wallet,
			CounterpartKind: "wallet", CounterpartID: funder,
			Relation: "initial_funding_in", VerificationStatus: status,
			EvidenceKey: signature + ":initial_funding", Source: "solana_jsonparsed_instruction",
			Signature: signature, Slot: slot, ObservedAt: observedAt, AmountNative: 1.25,
			Metadata: map[string]any{
				"actor_role": "funded_wallet", "source_wallet": funder,
				"destination_wallet": wallet, "program": "system",
				"history_complete": true, "persistent_actor_index": true,
			},
		}
	}
	put(fundingEvidence(creatorA, fmt.Sprintf("funding-a-%d", nonce), 101, "verified", baseTime))
	put(fundingEvidence(creatorB, fmt.Sprintf("funding-b-%d", nonce), 102, "observed", baseTime.Add(time.Hour)))

	creatorEvidence := func(wallet, mint string, index int) ActorDefenseEvidenceRecord {
		return ActorDefenseEvidenceRecord{
			Network: network, ActorWallet: wallet,
			CounterpartKind: "token", CounterpartID: mint,
			Relation: "created_token", VerificationStatus: "observed",
			EvidenceKey: fmt.Sprintf("creator-%d-%d", nonce, index), Source: "funding_cluster_memory_test",
			ObservedAt: baseTime.Add(time.Duration(index+2) * time.Hour), TokenMint: mint,
			Metadata: map[string]any{"actor_role": "creator_deployer", "program": "pump.fun", "persistent_actor_index": true},
		}
	}
	put(creatorEvidence(creatorA, tokenA, 1))
	put(creatorEvidence(creatorA, tokenB, 2))
	put(creatorEvidence(creatorB, tokenC, 3))

	put(ActorDefenseEvidenceRecord{
		Network: network, ActorWallet: creatorA,
		CounterpartKind: "token", CounterpartID: tokenA,
		Relation: "dominant_holder_of", VerificationStatus: "observed",
		EvidenceKey: fmt.Sprintf("dominant-%d", nonce), Source: "funding_cluster_memory_test",
		ObservedAt: baseTime.Add(6 * time.Hour), TokenMint: tokenA,
		Metadata: map[string]any{"actor_role": "dominant_holder", "holder_percentage": 34.5, "persistent_actor_index": true},
	})

	put(ActorDefenseEvidenceRecord{
		Network: network, ActorWallet: creatorB,
		CounterpartKind: "pool", CounterpartID: fmt.Sprintf("Pool%d", nonce),
		Relation: "liquidity_remove_activity", VerificationStatus: "observed",
		EvidenceKey: fmt.Sprintf("liquidity-%d", nonce), Source: "funding_cluster_memory_test",
		ObservedAt: baseTime.Add(7 * time.Hour), TokenMint: tokenC,
		Metadata: map[string]any{"actor_role": "liquidity_operator", "persistent_actor_index": true},
	})

	trackA := ActorDefenseTrack{Network: network, TargetKind: "wallet", TargetID: creatorA, State: "alerted", CreatedTokenCount: 2}
	if err := store.upsertTrack(ctx, &trackA); err != nil {
		t.Fatal(err)
	}
	trackB := ActorDefenseTrack{Network: network, TargetKind: "wallet", TargetID: creatorB, State: "correlated", CreatedTokenCount: 1}
	if err := store.upsertTrack(ctx, &trackB); err != nil {
		t.Fatal(err)
	}

	report, err := LoadPersistentFundingClusterHistory(ctx, db, creatorA, network, 8, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Complete || !report.Available || report.Status != "persistent_funding_history_observed" || report.SourceCount != 1 {
		t.Fatalf("unexpected funding-cluster report: %+v", report)
	}
	if report.VerdictAuthority || report.SameOperatorClaim || report.RealWorldIdentityClaim || report.WrongdoingClaim {
		t.Fatalf("funding-cluster memory acquired prohibited authority: %+v", report)
	}
	source := report.Sources[0]
	if source.Wallet != funder || !source.DirectSourceOfSubject {
		t.Fatalf("unexpected source: %+v", source)
	}
	if source.FundedActorCount != 2 || source.VerifiedFundedActorCount != 1 || source.ObservedFundedActorCount != 1 {
		t.Fatalf("unexpected funded actor counts: %+v", source)
	}
	if source.CreatorActorCount != 2 || source.CreatedTokenCount != 3 || source.RepeatCreatorCount != 1 {
		t.Fatalf("unexpected creator history: %+v", source)
	}
	if source.DominantHolderActorCount != 1 || source.LiquidityRemovalActors != 1 {
		t.Fatalf("unexpected behavior history: %+v", source)
	}
	if source.AlertedTrackCount != 1 || source.CorrelatedTrackCount != 1 || source.VerifiedTrackCount != 0 {
		t.Fatalf("unexpected threat-track history: %+v", source)
	}
	if len(source.Members) != 2 {
		t.Fatalf("unexpected members: %+v", source.Members)
	}

	funderReport, err := LoadPersistentFundingClusterHistory(ctx, db, funder, network, 8, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !funderReport.Available || funderReport.SourceCount != 1 || funderReport.Sources[0].Wallet != funder {
		t.Fatalf("funder-centric history missing: %+v", funderReport)
	}
	if funderReport.Sources[0].DirectSourceOfSubject {
		t.Fatalf("funder-centric source must not claim the funder funded itself: %+v", funderReport.Sources[0])
	}
}
