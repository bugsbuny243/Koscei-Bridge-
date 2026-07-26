package handlers

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestPublicProgramRiskQueriesPostgres17(t *testing.T) {
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
	db.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	// Temporary tables shadow the migrated production tables on this one test
	// connection. The query contract is exercised without mutating immutable
	// Defense OS evidence in a shared database.
	if _, err := db.ExecContext(ctx, `
		CREATE TEMP TABLE defense_program_deployments (
			snapshot_ref text PRIMARY KEY,
			program_id text NOT NULL,
			network text NOT NULL,
			loader_kind text NOT NULL,
			programdata_address text,
			upgrade_authority text,
			upgrade_authority_open boolean NOT NULL,
			executable boolean NOT NULL,
			canonical_binary_hash text NOT NULL,
			match_status text NOT NULL,
			snapshot_hash text NOT NULL,
			created_at timestamptz NOT NULL
		);
		CREATE TEMP TABLE defense_program_change_events (
			event_ref text PRIMARY KEY,
			program_id text NOT NULL,
			network text NOT NULL,
			change_types jsonb NOT NULL,
			severity text NOT NULL,
			summary text NOT NULL,
			event_hash text NOT NULL,
			created_at timestamptz NOT NULL,
			previous_snapshot_ref text NOT NULL,
			current_snapshot_ref text NOT NULL
		);`); err != nil {
		t.Fatal(err)
	}

	const (
		highPrevious = "KDS1-11111111111111111111111111111111"
		highCurrent  = "KDS1-22222222222222222222222222222222"
		highEvent    = "KDCE1-33333333333333333333333333333333"
		mediumPrev   = "KDS1-44444444444444444444444444444444"
		mediumCurr   = "KDS1-55555555555555555555555555555555"
		mediumEvent  = "KDCE1-66666666666666666666666666666666"
		unverified   = "KDS1-77777777777777777777777777777777"
		mismatch     = "KDS1-88888888888888888888888888888888"
	)
	if _, err := db.ExecContext(ctx, `
		INSERT INTO defense_program_deployments
		(snapshot_ref,program_id,network,loader_kind,programdata_address,upgrade_authority,
		 upgrade_authority_open,executable,canonical_binary_hash,match_status,snapshot_hash,created_at)
		VALUES
		($1,'ProgramHigh','solana-mainnet','bpf_upgradeable_loader','ProgramDataHigh',NULL,
		 false,true,'sha256:high-before','not_requested','sha256:snapshot-high-before','2026-01-01T00:00:00Z'),
		($2,'ProgramHigh','solana-mainnet','bpf_upgradeable_loader','ProgramDataHigh','AuthorityHigh',
		 true,true,'sha256:high-after','not_requested','sha256:snapshot-high-after','2026-01-02T00:00:00Z'),
		($3,'ProgramMedium','solana-mainnet','bpf_upgradeable_loader','ProgramDataMedium','AuthorityMedium',
		 true,true,'sha256:medium-before','not_requested','sha256:snapshot-medium-before','2026-01-01T00:00:00Z'),
		($4,'ProgramMedium','solana-mainnet','bpf_upgradeable_loader','ProgramDataMedium',NULL,
		 false,true,'sha256:medium-after','not_requested','sha256:snapshot-medium-after','2026-01-02T00:00:00Z'),
		($5,'ProgramUnverified','solana-mainnet','bpf_loader_v2',NULL,NULL,
		 false,true,'sha256:unverified','not_requested','sha256:snapshot-unverified','2026-01-03T00:00:00Z'),
		($6,'ProgramMismatch','solana-mainnet','bpf_loader_v2',NULL,NULL,
		 false,true,'sha256:mismatch','mismatched','sha256:snapshot-mismatch','2026-01-04T00:00:00Z')`,
		highPrevious, highCurrent, mediumPrev, mediumCurr, unverified, mismatch); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO defense_program_change_events
		(event_ref,program_id,network,change_types,severity,summary,event_hash,created_at,previous_snapshot_ref,current_snapshot_ref)
		VALUES
		($1,'ProgramHigh','solana-mainnet','["upgrade_authority_opened"]'::jsonb,'high',
		 'Upgrade authority opened','sha256:event-high','2026-01-02T00:01:00Z',$2,$3),
		($4,'ProgramMedium','solana-mainnet','["upgrade_authority_revoked"]'::jsonb,'medium',
		 'Upgrade authority revoked','sha256:event-medium','2026-01-02T00:01:00Z',$5,$6)`,
		highEvent, highPrevious, highCurrent, mediumEvent, mediumPrev, mediumCurr); err != nil {
		t.Fatal(err)
	}

	h := &Handler{DB: db, DBRead: db}
	items, err := h.loadPublicProgramRisks(ctx, 10)
	if err != nil {
		t.Fatalf("list public program risks: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("public risks=%d want=2: %#v", len(items), items)
	}
	seen := map[string]publicProgramRisk{}
	for _, item := range items {
		seen[item.EventRef] = item
	}
	if item, ok := seen[highEvent]; !ok || item.Type != "program_deployment_changed" || item.Severity != "high" {
		t.Fatalf("high immutable change event missing or malformed: %#v", item)
	}
	if item, ok := seen[mismatch]; !ok || item.Type != "program_control_risk_observed" || item.Severity != "critical" {
		t.Fatalf("verified mismatch snapshot missing or malformed: %#v", item)
	}
	for _, forbidden := range []string{mediumEvent, mediumCurr, unverified} {
		if _, exists := seen[forbidden]; exists {
			t.Fatalf("non-public evidence %s entered public program risks", forbidden)
		}
	}

	for _, ref := range []string{highEvent, highCurrent, mismatch} {
		if _, err := h.loadPublicProgramRiskByRef(ctx, ref); err != nil {
			t.Fatalf("public detail query %s: %v", ref, err)
		}
	}
	for _, ref := range []string{mediumEvent, mediumCurr, unverified, "KDCE1-00000000000000000000000000000000"} {
		_, err := h.loadPublicProgramRiskByRef(ctx, ref)
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("non-public detail %s error=%v want sql.ErrNoRows", ref, err)
		}
	}
}
