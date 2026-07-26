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
	// Cost-safe defaults keep enough concurrency for the current API while
	// allowing Neon's compute endpoint to become connection-idle quickly.
	db.SetMaxOpenConns(envInt("DB_MAX_OPEN_CONNS", 5))
	db.SetMaxIdleConns(envNonNegativeInt("DB_MAX_IDLE_CONNS", 1))
	db.SetConnMaxLifetime(time.Duration(envInt("DB_CONN_MAX_LIFETIME_SECONDS", 600)) * time.Second)
	db.SetConnMaxIdleTime(time.Duration(envInt("DB_CONN_MAX_IDLE_SECONDS", 60)) * time.Second)
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
		UPDATE entitlements
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

	return nil
}

func runMigrations(db *sql.DB) (int, int, error) {
	applied := 0
	skipped := 0
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return 0, 0, err
	}
	files, err := migrationSQLFiles()
	if err != nil {
		return 0, 0, err
	}
	if len(files) == 0 {
		log.Printf("warning: no migrations found in known paths; continuing with schema verification")
	}
	for _, f := range files {
		v := filepath.Base(f)
		var exists string
		err = db.QueryRow(`SELECT version FROM schema_migrations WHERE version=$1`, v).Scan(&exists)
		if err == nil {
			skipped++
			continue
		}
		if err != sql.ErrNoRows {
			return applied, skipped, err
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return applied, skipped, err
		}
		if _, err := db.Exec(string(b)); err != nil {
			return applied, skipped, fmt.Errorf("migration failed: %s %w", v, err)
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations (version) VALUES ($1)`, v); err != nil {
			return applied, skipped, err
		}
		applied++
	}
	return applied, skipped, nil
}

func migrationSQLFiles() ([]string, error) {
	candidates := []string{
		"migrations",
		filepath.Join("/app", "migrations"),
		filepath.Join("koschei", "api", "migrations"),
	}
	if configured := strings.TrimSpace(os.Getenv("MIGRATIONS_DIR")); configured != "" {
		candidates = append([]string{configured}, candidates...)
	}
	seen := map[string]bool{}
	for _, dir := range candidates {
		dir = strings.TrimSpace(dir)
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true
		files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			continue
		}
		sort.Strings(files)
		log.Printf("migrations path selected: %s (%d files)", dir, len(files))
		return files, nil
	}
	return nil, nil
}

func verifySchema(db *sql.DB) error {
	required := []string{"schema_migrations", "plans", "app_user_profiles", "entitlements", "payment_requests", "credit_events", "generation_jobs", "model_route_logs", "runtime_projects", "runtime_tasks", "runtime_logs", "owner_client_orders", "owner_order_requirements", "owner_order_assets", "owner_delivery_packages", "owner_revision_requests", "owner_profit_records", "owner_service_templates", "analytics_events", "grant_opportunities", "koschei_modules", "risk_assessments", "tx_decodes", "web3_jobs", "mev_protection_events", "whale_clusters", "cex_flows", "liquidity_drain_alerts", "dao_treasuries", "proposal_risks", "exploit_simulation_runs", "bridge_risk_events", "por_monitor_snapshots"}
	for _, t := range required {
		var ok bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=$1)`, t).Scan(&ok); err != nil || !ok {
			return fmt.Errorf("required table missing: %s", t)
		}
	}
	requiredColumns := map[string][]string{
		"app_user_profiles": {"id", "auth_subject", "email", "plan_id", "credits", "created_at", "updated_at"},
		"entitlements":      {"id", "email", "plan_id", "outputs_total", "outputs_remaining", "status", "created_at", "updated_at"},
		"api_keys":          {"id", "auth_subject", "email", "name", "key_prefix", "key_hash", "status", "monthly_limit", "rate_limit_per_minute", "created_at"},
	}
	for table, columns := range requiredColumns {
		for _, column := range columns {
			var ok bool
			if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name=$1 AND column_name=$2)`, table, column).Scan(&ok); err != nil || !ok {
				return fmt.Errorf("required column missing: %s.%s", table, column)
			}
		}
	}
	return nil
}
