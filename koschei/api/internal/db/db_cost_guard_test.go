package db

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestNormalizeDatabaseURLAddsApplicationName(t *testing.T) {
	t.Setenv("DB_APPLICATION_NAME", "koschei-cost-test")
	t.Setenv("DATABASE_URL_ALLOW_POOLER", "1")

	raw := "postgres://user:pass@example.neon.tech/neondb?sslmode=require"
	normalized := normalizeDatabaseURL(raw)
	parsed, err := url.Parse(normalized)
	if err != nil {
		t.Fatalf("parse normalized URL: %v", err)
	}
	if got := parsed.Query().Get("application_name"); got != "koschei-cost-test" {
		t.Fatalf("application_name=%q", got)
	}
}

func TestNormalizeDatabaseURLPreservesExplicitApplicationName(t *testing.T) {
	t.Setenv("DB_APPLICATION_NAME", "ignored")
	t.Setenv("DATABASE_URL_ALLOW_POOLER", "1")

	raw := "postgres://user:pass@example.neon.tech/neondb?sslmode=require&application_name=explicit"
	normalized := normalizeDatabaseURL(raw)
	parsed, err := url.Parse(normalized)
	if err != nil {
		t.Fatalf("parse normalized URL: %v", err)
	}
	if got := parsed.Query().Get("application_name"); got != "explicit" {
		t.Fatalf("application_name=%q", got)
	}
}

func TestNormalizeDatabaseURLPoolerPolicy(t *testing.T) {
	raw := "postgres://user:pass@ep-example-pooler.c-3.eu-central-1.aws.neon.tech/neondb?sslmode=require"

	t.Setenv("DATABASE_URL_ALLOW_POOLER", "0")
	direct := normalizeDatabaseURL(raw)
	if strings.Contains(direct, "-pooler.") {
		t.Fatalf("pooler host was not normalized: %s", direct)
	}

	t.Setenv("DATABASE_URL_ALLOW_POOLER", "1")
	pooled := normalizeDatabaseURL(raw)
	if !strings.Contains(pooled, "-pooler.") {
		t.Fatalf("explicit pooler opt-in was ignored: %s", pooled)
	}
}

func TestEnvNonNegativeIntAllowsZero(t *testing.T) {
	const key = "KOSCHEI_TEST_NON_NEGATIVE_INT"
	if err := os.Setenv(key, "0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Unsetenv(key) })
	if got := envNonNegativeInt(key, 3); got != 0 {
		t.Fatalf("got=%d", got)
	}
}
