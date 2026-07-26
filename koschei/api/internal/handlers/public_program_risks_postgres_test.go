package handlers

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
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
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := db.ExecContext(ctx, `
		CREATE TEMP TABLE defense_program_deployments (
			snapshot_ref text PRIMARY KEY, program_id text NOT NULL, network text NOT NULL,
			loader_kind text NOT NULL, programdata_address text, upgrade_authority text,
			upgrade_authority_open boolean NOT NULL, executable boolean NOT NULL,
			canonical_binary_hash text NOT NULL, match_status text NOT NULL,
			evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb, created_at timestamptz NOT NULL
		);
		CREATE TEMP TABLE defense_program_change_events (
			event_ref text PRIMARY KEY, monitor_ref text NOT NULL, program_id text NOT NULL, network text NOT NULL,
			change_types jsonb NOT NULL, severity text NOT NULL, summary text NOT NULL,
			evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb, created_at timestamptz NOT NULL,
			previous_snapshot_ref text NOT NULL, current_snapshot_ref text NOT NULL
		);
		CREATE TEMP TABLE program_risk_publications (
			evidence_ref text PRIMARY KEY, status text NOT NULL, public_title text NOT NULL DEFAULT '',
			public_summary text NOT NULL DEFAULT '', published_by text NOT NULL, published_at timestamptz
		);`); err != nil {
		t.Fatal(err)
	}

	const (
		oldRisk      = "KDS1-11111111111111111111111111111111"
		currentRisk  = "KDS1-22222222222222222222222222222222"
		publicEvent  = "KDCE1-33333333333333333333333333333333"
		privateEvent = "KDCE1-44444444444444444444444444444444"
		sourceOnly   = "KDCE1-55555555555555555555555555555555"
		mismatch     = "KDS1-66666666666666666666666666666666"
		privateRisk  = "KDS1-77777777777777777777777777777777"
	)
	if _, err := db.ExecContext(ctx, `
		INSERT INTO defense_program_deployments
		(snapshot_ref,program_id,network,loader_kind,programdata_address,upgrade_authority,upgrade_authority_open,executable,canonical_binary_hash,match_status,evidence_refs,created_at)
		VALUES
		($1,'ProgramA','solana-mainnet','bpf_upgradeable_loader','PD-A',NULL,false,true,'sha256:a-old','matched_full_binary','["rpc:getAccountInfo:ProgramA"]','2026-01-01T00:00:00Z'),
		($2,'ProgramA','solana-mainnet','bpf_upgradeable_loader','PD-A','AuthorityA',true,true,'sha256:a-new','not_requested','["rpc:getAccountInfo:ProgramA","artifact:KDA1-private"]','2026-01-02T00:00:00Z'),
		($3,'ProgramMismatch','solana-mainnet','bpf_loader_v2',NULL,NULL,false,true,'sha256:mismatch','mismatched','["rpc:getAccountInfo:ProgramMismatch"]','2026-01-04T00:00:00Z'),
		($4,'ProgramPrivate','solana-mainnet','bpf_upgradeable_loader','PD-P','AuthorityP',true,true,'sha256:private','not_requested','["rpc:getAccountInfo:ProgramPrivate"]','2026-01-05T00:00:00Z')`,
		oldRisk, currentRisk, mismatch, privateRisk); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO defense_program_change_events
		(event_ref,monitor_ref,program_id,network,change_types,severity,summary,evidence_refs,created_at,previous_snapshot_ref,current_snapshot_ref)
		VALUES
		($1,'KDM1-a','ProgramA','solana-mainnet','["bytecode_changed"]','critical','Bytecode changed',jsonb_build_array('deployment_snapshot:'||$2,'deployment_snapshot:'||$3,'artifact:KDA1-private'),'2026-01-02T00:01:00Z',$2,$3),
		($4,'KDM1-a','ProgramA','solana-mainnet','["upgrade_authority_changed"]','high','Private event',jsonb_build_array('deployment_snapshot:'||$2),'2026-01-02T00:02:00Z',$2,$3),
		($5,'KDM1-a','ProgramA','solana-mainnet','["source_match_lost"]','high','Manifest removed',jsonb_build_array('deployment_snapshot:'||$2),'2026-01-02T00:03:00Z',$2,$3)`,
		publicEvent, oldRisk, currentRisk, privateEvent, sourceOnly); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO program_risk_publications(evidence_ref,status,public_title,public_summary,published_by,published_at)
		VALUES
		($1,'public','','','user:test',now()),
		($2,'draft','','','user:test',NULL),
		($3,'public','','','user:test',now()),
		($4,'public','','','user:test',now()),
		($5,'draft','','','user:test',NULL)`, publicEvent, privateEvent, sourceOnly, mismatch, privateRisk); err != nil {
		t.Fatal(err)
	}

	h := &Handler{DB: db, DBRead: db}
	items, err := h.loadPublicProgramRisks(ctx, 20)
	if err != nil {
		t.Fatalf("list public program risks: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("public risks=%d want=2: %#v", len(items), items)
	}
	seen := map[string]publicProgramRisk{}
	for _, item := range items {
		seen[item.EventRef] = item
		if item.VerificationHash == "" || len(item.VerificationPayload) == 0 {
			t.Fatalf("risk is not publicly verifiable: %#v", item)
		}
		for _, ref := range item.EvidenceRefs {
			if strings.HasPrefix(ref, "artifact:") {
				t.Fatalf("private artifact leaked: %#v", item)
			}
		}
		if item.EvidenceRows != len(item.EvidenceRefs) {
			t.Fatalf("invented evidence count: %#v", item)
		}
	}
	if event, ok := seen[publicEvent]; !ok || event.Decision != "BLOCK" || event.Severity != "critical" {
		t.Fatalf("public chain event missing or malformed: %#v", event)
	}
	if !containsPublicRiskType(seen[publicEvent].RiskTypes, "upgrade_authority_open") {
		t.Fatalf("current authority risk was lost during event dedup: %#v", seen[publicEvent])
	}
	if snap, ok := seen[mismatch]; !ok || snap.Type != "program_control_risk_observed" || snap.Decision != "BLOCK" {
		t.Fatalf("public current mismatch missing: %#v", snap)
	}
	for _, forbidden := range []string{privateEvent, sourceOnly, privateRisk, oldRisk, currentRisk} {
		if _, exists := seen[forbidden]; exists {
			t.Fatalf("non-public or superseded evidence %s entered feed", forbidden)
		}
	}

	for _, ref := range []string{publicEvent, mismatch} {
		if _, err := h.loadPublicProgramRiskByRef(ctx, ref); err != nil {
			t.Fatalf("public detail %s: %v", ref, err)
		}
	}
	for _, ref := range []string{privateEvent, sourceOnly, privateRisk, oldRisk, currentRisk, "KDCE1-00000000000000000000000000000000"} {
		_, err := h.loadPublicProgramRiskByRef(ctx, ref)
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("private/superseded detail %s error=%v want sql.ErrNoRows", ref, err)
		}
	}
}

func containsPublicRiskType(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
