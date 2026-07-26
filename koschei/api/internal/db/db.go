package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

func Connect(databaseURL string) (*sql.DB, error) {
	db, err := open(databaseURL)
	if err != nil {
		return nil, err
	}
	applied, skipped, err := runMigrations(db)
	if err != nil {
		return nil, err
	}
	log.Printf("migrations applied/skipped: %d/%d", applied, skipped)
	if err := verifySchema(db); err != nil {
		return nil, fmt.Errorf("schema verification failed: %w", err)
	}
	if err := ensureCanonicalPlans(db); err != nil {
		return nil, fmt.Errorf("canonical plans sync failed: %w", err)
	}
	log.Printf("canonical plans synced")
	return db, nil
}

func ConnectReplica(databaseURL string) (*sql.DB, error) {
	return open(databaseURL)
}

func open(databaseURL string) (*sql.DB, error) {
	databaseURL = normalizeDatabaseURL(databaseURL)
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, err
	}
	maxOpen := envInt("DB_MAX_OPEN_CONNS", 5)
	maxIdle := envNonNegativeInt("DB_MAX_IDLE_CONNS", 0)
	maxLifetime := time.Duration(envNonNegativeInt("DB_CONN_MAX_LIFETIME_SECONDS", 300)) * time.Second
	maxIdleTime := time.Duration(envNonNegativeInt("DB_CONN_MAX_IDLE_TIME_SECONDS", 60)) * time.Second
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(maxLifetime)
	db.SetConnMaxIdleTime(maxIdleTime)
	log.Printf("database pool configured: max_open=%d max_idle=%d max_lifetime=%s max_idle_time=%s", maxOpen, maxIdle, maxLifetime, maxIdleTime)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("db ping failed: %w", err)
	}
	return db, nil
}

func normalizeDatabaseURL(databaseURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(databaseURL))
	if err != nil || parsed.Host == "" {
		return databaseURL
	}
	if strings.TrimSpace(os.Getenv("DATABASE_URL_ALLOW_POOLER")) != "1" {
		host := parsed.Hostname()
		if strings.Contains(host, "-pooler.") {
			directHost := strings.Replace(host, "-pooler.", ".", 1)
			if port := parsed.Port(); port != "" {
				parsed.Host = directHost + ":" + port
			} else {
				parsed.Host = directHost
			}
			log.Printf("database host normalized from neon pooler to direct connection")
		}
	}
	query := parsed.Query()
	if strings.TrimSpace(query.Get("application_name")) == "" {
		applicationName := strings.TrimSpace(os.Getenv("DB_APPLICATION_NAME"))
		if applicationName == "" {
			applicationName = "koschei-api"
		}
		query.Set("application_name", applicationName)
		parsed.RawQuery = query.Encode()
	}
	return parsed.String()
}

func envInt(name string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			return parsed
		}
	}
	return fallback
}

func envNonNegativeInt(name string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			return parsed
		}
	}
	return fallback
}

func ensureCanonicalPlans(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS plans (
		id text PRIMARY KEY,
		name text NOT NULL,
		price_try integer NOT NULL DEFAULT 0,
		monthly_credits integer NOT NULL DEFAULT 0,
		is_active boolean NOT NULL DEFAULT true,
		created_at timestamptz NOT NULL DEFAULT now(),
		updated_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return err
	}
	if _, err := db.Exec(`ALTER TABLE plans ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now()`); err != nil {
		return err
	}
	if _, err := db.Exec(`ALTER TABLE plans ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now()`); err != nil {
		return err
	}

	canonicalPlans := []struct {
		id             string
		name           string
		priceTry       int
		monthlyCredits int
		isActive       bool
	}{
		{id: "free", name: "Free", priceTry: 0, monthlyCredits: 0, isActive: true},
		{id: "starter", name: "Starter", priceTry: 899, monthlyCredits: 25, isActive: true},
		{id: "professional", name: "Professional", priceTry: 2299, monthlyCredits: 100, isActive: true},
		{id: "enterprise", name: "Enterprise", priceTry: 4999, monthlyCredits: 300, isActive: true},
		{id: "builder", name: "Legacy Builder", priceTry: 2299, monthlyCredits: 100, isActive: false},
		{id: "pro", name: "Legacy Pro", priceTry: 2299, monthlyCredits: 100, isActive: false},
		{id: "studio", name: "Legacy Studio", priceTry: 4999, monthlyCredits: 300, isActive: false},
	}

	for _, plan := range canonicalPlans {
		if _, err := db.Exec(`
			INSERT INTO plans (id, name, price_try, monthly_credits, is_active)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (id) DO UPDATE
			SET name = EXCLUDED.name,
				price_try = EXCLUDED.price_try,
				monthly_credits = EXCLUDED.monthly_credits,
				is_active = EXCLUDED.is_active,
				updated_at = now()
		`, plan.id, plan.name, plan.priceTry, plan.monthlyCredits, plan.isActive); err != nil {
			return err
		}
	}

	if _, err := db.Exec(`
		UPDATE app_user_profiles
		SET plan_id = CASE lower(COALESCE(plan_id,''))
			WHEN 'builder' THEN 'professional'
			WHEN 'pro' THEN 'professional'
			WHEN 'studio' THEN 'enterprise'
			ELSE plan_id
		END,
		updated_at = now()
		WHERE lower(COALESCE(plan_id,'')) IN ('builder','pro','studio')
	`); err != nil {
		return err
	}

	if _, err := db.Exec(`
		UPDATE users
		SET plan = CASE lower(COALESCE(plan,''))
			WHEN 'builder' THEN 'professional'
			WHEN 'pro' THEN 'professional'
			WHEN 'studio' THEN 'enterprise'
			ELSE plan
		END,
		updated_at = now()
		WHERE lower(COALESCE(plan,'')) IN ('builder','pro','studio')
	`); err != nil {
		return err
	}

	return nil
}

func runMigrations(db *sql.DB) (int, int, error) {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return 0, 0, err
	}

	migrationDir := os.Getenv("MIGRATIONS_DIR")
	if migrationDir == "" {
		migrationDir = filepath.Join(".", "migrations")
	}
	entries, err := os.ReadDir(migrationDir)
	if err != nil {
		fallback := filepath.Join("/app", "migrations")
		entries, err = os.ReadDir(fallback)
		if err != nil {
			return 0, 0, fmt.Errorf("read migrations dir: %w", err)
		}
		migrationDir = fallback
	}

	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		files = append(files, entry.Name())
	}
	sort.Strings(files)

	applied := 0
	skipped := 0
	for _, name := range files {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, name).Scan(&exists); err != nil {
			return applied, skipped, err
		}
		if exists {
			skipped++
			continue
		}
		contents, err := os.ReadFile(filepath.Join(migrationDir, name))
		if err != nil {
			return applied, skipped, err
		}
		tx, err := db.Begin()
		if err != nil {
			return applied, skipped, err
		}
		// #nosec G701 -- SQL is read only from version-controlled migration files
		// packaged with the application; no request, database or operator string is
		// interpolated into the migration contents at runtime.
		if _, err := tx.Exec(string(contents)); err != nil {
			_ = tx.Rollback()
			return applied, skipped, fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version) VALUES($1)`, name); err != nil {
			_ = tx.Rollback()
			return applied, skipped, err
		}
		if err := tx.Commit(); err != nil {
			return applied, skipped, err
		}
		applied++
	}
	return applied, skipped, nil
}

func verifySchema(db *sql.DB) error {
	checks := []struct {
		name string
		sql  string
	}{
		{name: "users", sql: `SELECT 1 FROM users LIMIT 1`},
		{name: "plans", sql: `SELECT 1 FROM plans LIMIT 1`},
		{name: "entitlements", sql: `SELECT 1 FROM entitlements LIMIT 1`},
		{name: "api_keys", sql: `SELECT 1 FROM api_keys LIMIT 1`},
		{name: "usage_events", sql: `SELECT 1 FROM usage_events LIMIT 1`},
		{name: "security_audit_log", sql: `SELECT 1 FROM security_audit_log LIMIT 1`},
	}
	for _, check := range checks {
		if _, err := db.Exec(check.sql); err != nil {
			return fmt.Errorf("required table %s unavailable: %w", check.name, err)
		}
	}
	return nil
}
