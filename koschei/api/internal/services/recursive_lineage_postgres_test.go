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

func TestRecursiveLineageReverseFunderTokenHistoryPostgres17(t *testing.T) {
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
	creator := fmt.Sprintf("RecursiveCreator%d", nonce)
	funder := fmt.Sprintf("RecursiveFunder%d", nonce)
	mint := fmt.Sprintf("RecursiveMint%d", nonce)
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM security_actor_evidence WHERE network=$1 AND (actor_wallet=$2 OR counterpart_id=$2 OR actor_wallet=$3 OR counterpart_id=$3)`, network, creator, funder)
	}()

	store := NewActorDefenseStore(db)
	evidence := ActorDefenseEvidenceRecord{
		Network: network, ActorWallet: creator,
		CounterpartKind: "wallet", CounterpartID: funder,
		Relation: "initial_funding_in", VerificationStatus: "verified",
		EvidenceKey: fmt.Sprintf("funding-%d:token:%s", nonce, mint),
		Source: "recursive_lineage_postgres_test",
		Signature: fmt.Sprintf("sig-%d", nonce), Slot: 4242,
		ObservedAt: time.Now().UTC().Add(-time.Hour), AmountNative: 1.5, TokenMint: mint,
		Metadata: map[string]any{
			"actor_role": "funded_wallet", "source_wallet": funder,
			"destination_wallet": creator, "program": "system",
			"token_context": mint, "token_scoped_funding_lineage": true,
		},
	}
	if err := store.UpsertEvidence(ctx, evidence); err != nil {
		t.Fatal(err)
	}

	history, err := store.LoadBoundedRecursiveTokenHistory(ctx, funder, network, 20)
	if err != nil {
		t.Fatal(err)
	}
	if history.FundingRowsRead != 1 {
		t.Fatalf("expected one reverse funding row, got %+v", history)
	}
	if len(history.Tokens) != 1 || history.Tokens[0].Mint != mint {
		t.Fatalf("funder token lineage did not recover token context: %+v", history.Tokens)
	}
	roles := map[string]bool{}
	for _, role := range history.Tokens[0].Roles {
		roles[role] = true
	}
	if !roles["funder"] {
		t.Fatalf("reverse funding history must expose the funder role: %+v", history.Tokens[0])
	}
	if len(history.Tokens[0].Evidence) == 0 {
		t.Fatalf("reverse funding token relation must retain an explanatory evidence line")
	}
}
