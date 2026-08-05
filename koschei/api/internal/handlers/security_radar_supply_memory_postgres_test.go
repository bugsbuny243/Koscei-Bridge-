package handlers

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestRadarDetailStructuralContextIncludesSupplyPostgres17(t *testing.T) {
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

	target := "ci-handler-supply-" + time.Now().UTC().Format("20060102150405.000000000")
	network := "solana-mainnet"
	observedAt := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM token_structural_signals WHERE target=$1 AND network=$2`, target, network)
	}()

	if _, err := db.ExecContext(ctx, `
		INSERT INTO token_structural_signals
			(target,network,token_supply,has_supply_data,supply_observed_at,observed_at,updated_at)
		VALUES ($1,$2,$3,true,$4,$4,$4)`, target, network, 1_250_000.25, observedAt); err != nil {
		t.Fatal(err)
	}

	out := (&Handler{DB: db}).radarDetailStructuralContext(ctx, target, network)
	if out["available"] != true || out["has_supply_data"] != true {
		t.Fatalf("availability=%#v", out)
	}
	if got := radarDetailNumber(out["token_supply"]); got != 1_250_000.25 {
		t.Fatalf("token_supply=%v", got)
	}
	if got := dossierString(out["supply_observed_at"]); got != observedAt.Format(time.RFC3339) {
		t.Fatalf("supply_observed_at=%q", got)
	}
	if out["has_holder_data"] != false || out["has_authority_data"] != false {
		t.Fatalf("supply-only row contaminated structural dimensions: %#v", out)
	}
}
