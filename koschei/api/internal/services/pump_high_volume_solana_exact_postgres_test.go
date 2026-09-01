package services

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestPumpHighVolumeSolanaIdentityIsCaseSensitivePostgres17(t *testing.T) {
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

	mintA := "AbCDefGHjkMNpQRstUVwxYZ123456789"
	mintB := "aBcdefghJKmnPqrSTuvWXyz123456789"
	if len(mintA) != len(mintB) {
		t.Fatal("test fixtures must remain equal length")
	}

	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM security_radar_events WHERE target IN ($1,$2)`, mintA, mintB)
	}
	cleanup()
	defer cleanup()

	_, err = db.ExecContext(ctx, `
		INSERT INTO security_radar_events (
			module_id,target,target_type,network,event_type,signals,raw_summary,source,created_at,updated_at
		) VALUES
			('pump_sybil_radar',$1,'token','solana-mainnet','pumpportal_token',
			 '{"token_name":"Upper","token_symbol":"UP"}'::jsonb,'{}'::jsonb,'pumpportal',now(),now()),
			('pump_sybil_radar',$2,'token','solana-mainnet','pumpportal_token',
			 '{"token_name":"Lower","token_symbol":"LOW"}'::jsonb,'{}'::jsonb,'pumpportal',now(),now())
	`, mintA, mintB)
	if err != nil {
		t.Fatal(err)
	}

	store := NewSecurityRadarStore(db)
	candidates, err := store.ListPumpPortalCandidatesExact(ctx, 10, time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	seenA, seenB := false, false
	for _, candidate := range candidates {
		switch candidate.Mint {
		case mintA:
			seenA = true
		case mintB:
			seenB = true
		}
	}
	if !seenA || !seenB {
		t.Fatalf("case-distinct Solana mints collapsed: seenA=%t seenB=%t candidates=%#v", seenA, seenB, candidates)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO security_radar_events (
			module_id,target,target_type,network,event_type,signals,raw_summary,source,created_at,updated_at
		) VALUES (
			'pump_sybil_radar',$1,'token','solana-mainnet',$2,
			'{"auto_scan_attempted":true}'::jsonb,'{}'::jsonb,$3,now(),now()
		)
	`, mintA, pumpHighVolumeEventType, PumpHighVolumeCanonicalSource)
	if err != nil {
		t.Fatal(err)
	}

	attemptedA, err := store.PumpHighVolumeAttemptedRecentlyExact(ctx, mintA, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	attemptedB, err := store.PumpHighVolumeAttemptedRecentlyExact(ctx, mintB, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !attemptedA {
		t.Fatal("exact attempted mint must be suppressed inside cooldown")
	}
	if attemptedB {
		t.Fatal("case-variant Solana mint must not inherit another mint's attempt cooldown")
	}
}
