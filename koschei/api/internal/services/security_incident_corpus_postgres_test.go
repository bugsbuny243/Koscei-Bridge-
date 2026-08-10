package services

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestSecurityIncidentCorpusPostgres17(t *testing.T) {
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
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	const (
		network = "solana-mainnet"
		targetA = "IncidentCorpusTargetA1111111111111111111111111111"
		actorA  = "IncidentCorpusActorA11111111111111111111111111111"
		eventA  = "incident-corpus-event-signature-a"
		verdictA = "incident-corpus-verdict-signature-a"
		targetB = "IncidentCorpusTargetB1111111111111111111111111111"
		actorB  = "IncidentCorpusActorB11111111111111111111111111111"
		eventB  = "incident-corpus-event-signature-b"
		verdictB = "incident-corpus-verdict-signature-b"
	)

	insertExit := func(target, actor, signature string, slot int64) {
		t.Helper()
		_, err := tx.ExecContext(ctx, `
			INSERT INTO security_actor_exit_events
			(actor_wallet,network,target,event_kind,evidence_state,signature,slot,observed_at,source_rule_id,detail)
			VALUES ($1,$2,$3,'liquidity_removal','verified',$4,$5,now()-interval '1 minute','A-001','{"ci":true}'::jsonb)
		`, actor, network, target, signature, slot)
		if err != nil {
			t.Fatal(err)
		}
	}
	insertVerdict := func(target, signature string, risk int) {
		t.Helper()
		_, err := tx.ExecContext(ctx, `
			INSERT INTO security_radar_verdicts
			(event_id,module_id,target,target_type,network,grade,risk_index,risk_level,verdict,recommendation,
			 evidence,signals,rule_version,signed,signature,source,created_at,updated_at)
			VALUES
			(NULL,'final_verdict_engine',$1,'token',$2,'F',$4,'critical','ci material verdict','review ci evidence',
			 '["verified ci evidence"]'::jsonb,'{"verified_evidence":true,"real_onchain_evidence":true}'::jsonb,
			 'ci-final-v1',true,$3,'ci',now(),now())
		`, target, network, signature, risk)
		if err != nil {
			t.Fatal(err)
		}
	}
	countForTarget := func(target string) int {
		t.Helper()
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM security_incident_corpus WHERE network=$1 AND target=$2`, network, target).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}

	// Event first: no signed material verdict means no confirmed corpus row.
	insertExit(targetA, actorA, eventA, 111)
	if got := countForTarget(targetA); got != 0 {
		t.Fatalf("event-only corpus count=%d want=0", got)
	}
	insertVerdict(targetA, verdictA, 91)
	if got := countForTarget(targetA); got != 1 {
		t.Fatalf("event-then-verdict corpus count=%d want=1", got)
	}

	// Verdict first: the later VERIFIED exit event must converge to the same corpus.
	insertVerdict(targetB, verdictB, 88)
	if got := countForTarget(targetB); got != 0 {
		t.Fatalf("verdict-only corpus count=%d want=0", got)
	}
	insertExit(targetB, actorB, eventB, 222)
	if got := countForTarget(targetB); got != 1 {
		t.Fatalf("verdict-then-event corpus count=%d want=1", got)
	}

	var incidentKey, recordHash, riskLevel string
	var eventSlot int64
	if err := tx.QueryRowContext(ctx, `
		SELECT incident_key,record_hash,risk_level,event_slot
		FROM security_incident_corpus WHERE network=$1 AND target=$2
	`, network, targetA).Scan(&incidentKey, &recordHash, &riskLevel, &eventSlot); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(incidentKey, "KIC1-") || len(incidentKey) != len("KIC1-")+64 {
		t.Fatalf("incident key=%q", incidentKey)
	}
	if !strings.HasPrefix(recordHash, "sha256:") || len(recordHash) != len("sha256:")+64 {
		t.Fatalf("record hash=%q", recordHash)
	}
	if riskLevel != "critical" || eventSlot != 111 {
		t.Fatalf("risk=%s event_slot=%d", riskLevel, eventSlot)
	}

	// Corpus rows are immutable. A savepoint lets the test prove the trigger and
	// then continue after PostgreSQL marks the failed statement aborted.
	if _, err := tx.ExecContext(ctx, `SAVEPOINT corpus_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE security_incident_corpus SET grade='A' WHERE incident_key=$1`, incidentKey); err == nil {
		t.Fatal("incident corpus update unexpectedly succeeded")
	}
	if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT corpus_immutable`); err != nil {
		t.Fatal(err)
	}

	// A later revision of the same signed verdict is a new immutable version and
	// points back to the previous row instead of rewriting it.
	_, err = tx.ExecContext(ctx, `
		UPDATE security_radar_verdicts
		SET risk_index=96,verdict='ci revised material verdict',updated_at=updated_at+interval '1 second'
		WHERE module_id='final_verdict_engine' AND signature=$1
	`, verdictA)
	if err != nil {
		t.Fatal(err)
	}
	if got := countForTarget(targetA); got != 2 {
		t.Fatalf("revised verdict corpus count=%d want=2", got)
	}
	var superseded int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM security_incident_corpus
		WHERE network=$1 AND target=$2 AND supersedes_incident_id IS NOT NULL
	`, network, targetA).Scan(&superseded); err != nil {
		t.Fatal(err)
	}
	if superseded != 1 {
		t.Fatalf("superseding versions=%d want=1", superseded)
	}
}
