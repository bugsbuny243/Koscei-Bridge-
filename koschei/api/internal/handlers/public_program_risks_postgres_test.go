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

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	h := &Handler{DB: db, DBRead: db}
	items, err := h.loadPublicProgramRisks(ctx, 10)
	if err != nil {
		t.Fatalf("list public program risks: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("fresh migrated database returned %d public program risks", len(items))
	}

	for _, ref := range []string{
		"KDCE1-00000000000000000000000000000000",
		"KDS1-00000000000000000000000000000000",
	} {
		_, err := h.loadPublicProgramRiskByRef(ctx, ref)
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("detail query %s error=%v want sql.ErrNoRows", ref, err)
		}
	}
}
