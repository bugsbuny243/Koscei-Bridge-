package services

import (
	"context"
	"database/sql"
	"math"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestStructuralSignalFloatRejectsNonFiniteValues(t *testing.T) {
	cases := []struct {
		name  string
		value any
		ok    bool
		want  float64
	}{
		{name: "float", value: 1250000.5, ok: true, want: 1250000.5},
		{name: "string", value: "42.25", ok: true, want: 42.25},
		{name: "zero", value: 0, ok: true, want: 0},
		{name: "nan", value: math.NaN(), ok: false},
		{name: "positive infinity", value: math.Inf(1), ok: false},
		{name: "negative infinity", value: math.Inf(-1), ok: false},
		{name: "invalid", value: "not-a-number", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := structuralSignalFloat(map[string]any{"token_supply": tc.value}, "token_supply")
			if ok != tc.ok {
				t.Fatalf("ok=%v want=%v value=%#v", ok, tc.ok, tc.value)
			}
			if ok && got != tc.want {
				t.Fatalf("got=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestSupplyMemoryNeverCreatesStructuralRiskFloor(t *testing.T) {
	now := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)
	cached := tokenStructuralSignals{
		TokenSupply:      1_000_000,
		HasSupplyData:    true,
		SupplyObservedAt: ptrStructuralTime(now.Add(-time.Hour)),
	}
	floor, observedAt := cached.structuralFloor(now)
	if floor != 0 || !observedAt.IsZero() {
		t.Fatalf("supply-only memory changed floor: floor=%d observed_at=%s", floor, observedAt)
	}
}

func TestVerifiedSupplyMemoryPostgres17(t *testing.T) {
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

	target := "ci-supply-memory-" + time.Now().UTC().Format("20060102150405.000000000")
	network := "solana-mainnet"
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM token_structural_signals WHERE target=$1 AND network=$2`, target, network)
	}()

	store := NewSecurityRadarStore(db)
	capture := func(module string, signed, verified bool, value any) {
		t.Helper()
		store.captureStructuralSignals(ctx, SecurityRadarVerdictRecord{
			ModuleID: module,
			Target:   target,
			Network:  network,
			Signed:   signed,
			Signature: "ci-supply-signature",
			Signals: map[string]any{
				"verified_evidence": verified,
				"token_supply":      value,
			},
		})
	}

	capture(ModuleHolderConcentration, true, true, 1_000_000.5)
	assertStoredSupply(t, ctx, db, target, network, 1_000_000.5)

	capture(ModuleHolderConcentration, true, false, 2_000_000.0)
	capture(ModuleHolderConcentration, false, true, 2_000_000.0)
	capture(ModuleTokenAuthorityScanner, true, true, 2_000_000.0)
	capture(ModuleHolderConcentration, true, true, math.NaN())
	capture(ModuleHolderConcentration, true, true, -1.0)
	assertStoredSupply(t, ctx, db, target, network, 1_000_000.5)

	capture(ModuleHolderConcentration, true, true, "1250000.25")
	assertStoredSupply(t, ctx, db, target, network, 1_250_000.25)

	if floor, _, observedAt, ok := store.StructuralBaseline(ctx, target, network); ok || floor != 0 || !observedAt.IsZero() {
		t.Fatalf("supply-only row became a risk floor: floor=%d observed_at=%s ok=%v", floor, observedAt, ok)
	}
}

func assertStoredSupply(t *testing.T, ctx context.Context, db *sql.DB, target, network string, want float64) {
	t.Helper()
	var supply float64
	var hasSupply, hasHolder, hasAuthority bool
	var observedAt time.Time
	if err := db.QueryRowContext(ctx, `
		SELECT token_supply,has_supply_data,supply_observed_at,has_holder_data,has_authority_data
		FROM token_structural_signals
		WHERE target=$1 AND network=$2`, target, network).Scan(
		&supply, &hasSupply, &observedAt, &hasHolder, &hasAuthority,
	); err != nil {
		t.Fatal(err)
	}
	if supply != want || !hasSupply || observedAt.IsZero() {
		t.Fatalf("supply=%v want=%v has_supply=%v observed_at=%s", supply, want, hasSupply, observedAt)
	}
	if hasHolder || hasAuthority {
		t.Fatalf("supply-only capture contaminated other memory: holder=%v authority=%v", hasHolder, hasAuthority)
	}
}

func ptrStructuralTime(value time.Time) *time.Time { return &value }
