package services

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestActorExitEventFromEvidenceRequiresSignatureAndSlot(t *testing.T) {
	item := ActorDefenseEvidenceRecord{
		Network: "solana-mainnet", ActorWallet: "fixture-actor", TokenMint: "fixture-target",
		Relation: "liquidity_remove_activity", VerificationStatus: "verified",
		Slot: 100, ObservedAt: time.Now().UTC(),
		Metadata: map[string]any{"actor_signed": true, "creator_role_observed": true},
	}
	if _, ok := actorExitEventFromEvidence(item); ok {
		t.Fatal("event without transaction signature was accepted")
	}
	item.Signature = "fixture-signature"
	item.Slot = 0
	if _, ok := actorExitEventFromEvidence(item); ok {
		t.Fatal("event without positive slot was accepted")
	}
}

func TestActorExitEventFromEvidenceRejectsUnknownState(t *testing.T) {
	item := ActorDefenseEvidenceRecord{
		Network: "solana-mainnet", ActorWallet: "fixture-actor", TokenMint: "fixture-target",
		Relation: "dominant_holder_first_exit", VerificationStatus: "unexpected_status",
		Signature: "fixture-signature", Slot: 100, ObservedAt: time.Now().UTC(),
		Metadata: map[string]any{
			"unified_rule_id": UnifiedRuleDominantHolderFirstExit,
			"metrics":         map[string]any{"holder_wallet": "fixture-holder"},
		},
	}
	if _, ok := actorExitEventFromEvidence(item); ok {
		t.Fatal("unknown evidence state was promoted to an exit-event observation")
	}
}

func TestActorExitEventFromCreatorSellIsWithheld(t *testing.T) {
	item := ActorDefenseEvidenceRecord{
		Network: "solana-mainnet", ActorWallet: "fixture-actor", TokenMint: "fixture-target",
		Relation: "creator_sell_acceleration", VerificationStatus: "verified",
		Signature: "fixture-signature", Slot: 101, ObservedAt: time.Now().UTC(),
		Metadata: map[string]any{"unified_rule_id": UnifiedRuleCreatorSellAcceleration},
	}
	if _, ok := actorExitEventFromEvidence(item); ok {
		t.Fatal("aggregate creator-sell evidence was promoted to an event without transaction-level trade preservation")
	}
}

func TestActorExitEventCorpusPostgres17(t *testing.T) {
	databaseURL := os.Getenv("KOSCHEI_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KOSCHEI_TEST_DATABASE_URL is not set")
	}
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(2)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	suffix := time.Now().UTC().Format("20060102150405.000000000")
	actor := "fixture-exit-actor-" + suffix
	targetA := "fixture-exit-target-a-" + suffix
	targetB := "fixture-exit-target-b-" + suffix
	network := "solana-mainnet"
	store := NewActorDefenseStore(db)
	makeEvidence := func(target, signature string, slot int64) ActorDefenseEvidenceRecord {
		return ActorDefenseEvidenceRecord{
			Network: network, ActorWallet: actor,
			CounterpartKind: "pool", CounterpartID: "fixture-pool-" + target,
			Relation: "liquidity_remove_activity", VerificationStatus: "verified",
			EvidenceKey: signature + ":liquidity_remove", Source: "solana_jsonparsed_instruction",
			Signature: signature, Slot: slot, ObservedAt: time.Now().UTC(), TokenMint: target,
			Metadata: map[string]any{
				"actor_signed": true, "creator_role_observed": true,
				"pool_account": "fixture-pool-" + target, "program": "fixture-program",
			},
		}
	}

	first := makeEvidence(targetA, "fixture-exit-signature-a-"+suffix, 1001)
	if err := store.UpsertEvidence(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertEvidence(ctx, first); err != nil {
		t.Fatal(err)
	}
	var eventRows int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM security_actor_exit_events
		WHERE actor_wallet=$1 AND network=$2 AND target=$3`, actor, network, targetA).Scan(&eventRows); err != nil {
		t.Fatal(err)
	}
	if eventRows != 1 {
		t.Fatalf("same event rerun rows=%d want=1", eventRows)
	}
	var distinctTargets, verifiedEvents, observedEvents int
	if err := db.QueryRowContext(ctx, `
		SELECT distinct_targets_with_events,verified_event_count,observed_event_count
		FROM security_actor_exit_profiles WHERE actor_wallet=$1 AND network=$2`, actor, network).Scan(&distinctTargets, &verifiedEvents, &observedEvents); err != nil {
		t.Fatal(err)
	}
	if distinctTargets != 1 || verifiedEvents != 1 || observedEvents != 0 {
		t.Fatalf("profile after rerun targets=%d verified=%d observed=%d want 1/1/0", distinctTargets, verifiedEvents, observedEvents)
	}

	second := makeEvidence(targetB, "fixture-exit-signature-b-"+suffix, 1002)
	if err := store.UpsertEvidence(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `
		SELECT distinct_targets_with_events,verified_event_count,observed_event_count
		FROM security_actor_exit_profiles WHERE actor_wallet=$1 AND network=$2`, actor, network).Scan(&distinctTargets, &verifiedEvents, &observedEvents); err != nil {
		t.Fatal(err)
	}
	if distinctTargets != 2 || verifiedEvents != 2 || observedEvents != 0 {
		t.Fatalf("profile targets=%d verified=%d observed=%d want 2/2/0", distinctTargets, verifiedEvents, observedEvents)
	}

	recurrence, err := store.LoadActorExitRecurrence(ctx, actor, network, targetB)
	if err != nil {
		t.Fatal(err)
	}
	if recurrence.EvidenceStatus != "verified" || recurrence.DistinctTargetsWithEvents != 2 || len(recurrence.OtherTargets) != 1 || recurrence.OtherTargets[0] != targetA {
		t.Fatalf("recurrence=%#v", recurrence)
	}

	missingSignature := makeEvidence("fixture-exit-target-missing-"+suffix, "", 1003)
	missingSignature.EvidenceKey = "fixture-missing-signature-" + suffix
	if err := store.UpsertEvidence(ctx, missingSignature); err != nil {
		t.Fatal(err)
	}
	var missingRows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM security_actor_exit_events WHERE target=$1`, missingSignature.TokenMint).Scan(&missingRows); err != nil {
		t.Fatal(err)
	}
	if missingRows != 0 {
		t.Fatalf("signature-less evidence persisted %d event row(s)", missingRows)
	}

	creatorSell := ActorDefenseEvidenceRecord{
		Network: network, ActorWallet: actor,
		CounterpartKind: "token", CounterpartID: "fixture-sell-target-" + suffix,
		Relation: "creator_sell_acceleration", VerificationStatus: "verified",
		EvidenceKey: "fixture-sell-evidence-" + suffix, Source: "unified_manual_radar",
		Signature: "fixture-sell-signature-" + suffix, Slot: 1004, ObservedAt: time.Now().UTC(),
		TokenMint: "fixture-sell-target-" + suffix,
		Metadata:  map[string]any{"unified_rule_id": UnifiedRuleCreatorSellAcceleration},
	}
	if err := store.UpsertEvidence(ctx, creatorSell); err != nil {
		t.Fatal(err)
	}
	var creatorSellRows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM security_actor_exit_events WHERE actor_wallet=$1 AND event_kind='creator_sell'`, actor).Scan(&creatorSellRows); err != nil {
		t.Fatal(err)
	}
	if creatorSellRows != 0 {
		t.Fatalf("creator_sell persisted %d row(s) without transaction-level trade evidence", creatorSellRows)
	}
}
