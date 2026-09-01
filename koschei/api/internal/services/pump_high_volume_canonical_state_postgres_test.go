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

func TestPumpHighVolumeCanonicalReportStatePostgres17(t *testing.T) {
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

	mint := fmt.Sprintf("ci-pump-canonical-%d", time.Now().UnixNano())
	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM security_radar_verdicts WHERE target=$1`, mint)
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM web3_jobs WHERE target=$1`, mint)
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM security_radar_events WHERE target=$1`, mint)
	}
	cleanup()
	defer cleanup()

	_, err = db.ExecContext(ctx, `
		INSERT INTO security_radar_events (
			module_id,target,target_type,network,event_type,signals,source
		) VALUES (
			'pump_sybil_radar',$1,'token','solana-mainnet',$2,
			'{"token_name":"CI Pump","token_symbol":"CIP","creator_wallet":"ci-creator","volume_24h_usd":750000,"volume_threshold_usd":500000,"volume_pair_count":3,"volume_provider":"dexscreener","auto_scan_attempted":true}'::jsonb,
			$3
		)`, mint, pumpHighVolumeEventType, PumpHighVolumeCanonicalSource)
	if err != nil {
		t.Fatal(err)
	}

	// A legacy signed final row must not prove that the canonical Pump report ran.
	_, err = db.ExecContext(ctx, `
		INSERT INTO security_radar_verdicts (
			module_id,target,target_type,network,grade,risk_index,risk_level,verdict,
			recommendation,evidence,signals,rule_version,signed,source
		) VALUES (
			'final_verdict_engine',$1,'token','solana-mainnet','F',99,'critical','legacy_final',
			'legacy only','[]'::jsonb,'{}'::jsonb,'legacy-v1',true,$2
		)`, mint, PumpHighVolumeCanonicalSource)
	if err != nil {
		t.Fatal(err)
	}

	store := NewSecurityRadarStore(db)
	recent, err := store.PumpHighVolumeCanonicalReportCompletedRecently(ctx, mint, 6*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if recent {
		t.Fatal("legacy final_verdict_engine row must not satisfy canonical Pump report cooldown")
	}
	items, err := store.LatestPumpHighVolumeReportsExact(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	item := findPumpOwnerItem(items, mint)
	if item == nil {
		t.Fatalf("owner Pump projection did not include %s", mint)
	}
	if item.ReportStatus == "completed" {
		t.Fatalf("legacy final row incorrectly marked canonical report completed: %#v", item)
	}
	if item.RiskIndex != nil {
		t.Fatalf("legacy numeric risk index leaked into canonical owner projection: %#v", item.RiskIndex)
	}

	// Completion is authoritative for cooldown, but an unsigned final verdict must
	// remain visibly distinct from a signed canonical decision.
	var jobID string
	err = db.QueryRowContext(ctx, `
		INSERT INTO web3_jobs (
			job_type,status,network,target,request_payload,result_payload,progress,attempts,
			queued_at,started_at,completed_at,updated_at
		) VALUES (
			'canonical_investigation','completed','solana-mainnet',$1,
			jsonb_build_object('source',$2,'mode',$3,'dedupe_key','ci-pump-canonical'),
			'{"final_verdict":{"grade":"D","verdict":"verified_rule_triggered","ruleset_version":"koschei-unified-radar-rules-ci","signed":false,"decision_path":["verified actor evidence triggered deterministic rule"]}}'::jsonb,
			100,1,now(),now(),now(),now()
		) RETURNING id::text`, mint, PumpHighVolumeCanonicalSource, PumpHighVolumeCanonicalMode).Scan(&jobID)
	if err != nil {
		t.Fatal(err)
	}

	recent, err = store.PumpHighVolumeCanonicalReportCompletedRecently(ctx, mint, 6*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !recent {
		t.Fatal("completed canonical Pump investigation must satisfy report cooldown")
	}
	items, err = store.LatestPumpHighVolumeReportsExact(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	item = findPumpOwnerItem(items, mint)
	if item == nil {
		t.Fatalf("owner Pump projection lost %s after canonical job completion", mint)
	}
	if item.ReportStatus != "completed_unsigned" {
		t.Fatalf("unsigned canonical verdict must not be presented as signed completion: status=%q signals=%#v", item.ReportStatus, item.Signals)
	}
	if item.Verdict != "verified_rule_triggered" {
		t.Fatalf("canonical verdict not projected: %q", item.Verdict)
	}
	if got := pumpSignalString(item.Signals, "grade"); got != "D" {
		t.Fatalf("canonical grade projection=%q", got)
	}
	if pumpSignalBool(item.Signals, "signed") {
		t.Fatal("unsigned canonical verdict was projected as signed")
	}
	if got := pumpSignalString(item.Signals, "canonical_job_id"); got != jobID {
		t.Fatalf("canonical job provenance=%q want=%q", got, jobID)
	}

	_, err = db.ExecContext(ctx, `
		UPDATE web3_jobs
		SET result_payload=jsonb_set(
			jsonb_set(result_payload,'{final_verdict,signed}','true'::jsonb,true),
			'{final_verdict,signature}',to_jsonb('ci-canonical-signature'::text),true
		), updated_at=now()
		WHERE id=$1::uuid`, jobID)
	if err != nil {
		t.Fatal(err)
	}
	items, err = store.LatestPumpHighVolumeReportsExact(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	item = findPumpOwnerItem(items, mint)
	if item == nil {
		t.Fatalf("owner Pump projection lost %s after signed verdict update", mint)
	}
	if item.ReportStatus != "completed" {
		t.Fatalf("signed canonical verdict should be completed: status=%q", item.ReportStatus)
	}
	if !pumpSignalBool(item.Signals, "signed") {
		t.Fatal("signed canonical verdict was not projected as signed")
	}
	if got := pumpSignalString(item.Signals, "signature"); got != "ci-canonical-signature" {
		t.Fatalf("canonical signature projection=%q", got)
	}
}

func findPumpOwnerItem(items []PumpHighVolumeOwnerItem, mint string) *PumpHighVolumeOwnerItem {
	for i := range items {
		if items[i].Target == mint {
			return &items[i]
		}
	}
	return nil
}
