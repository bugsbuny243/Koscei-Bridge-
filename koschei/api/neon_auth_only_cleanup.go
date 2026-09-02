package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"koschei/api/internal/db"
)

func neonAuthOnlyPurgeRequested() bool {
	value := strings.TrimSpace(os.Getenv("KOSCHEI_NEON_AUTH_ONLY_PURGE"))
	return strings.EqualFold(value, "1") || strings.EqualFold(value, "true") || strings.EqualFold(value, "yes") || strings.EqualFold(value, "on")
}

func purgePublicApplicationTables(ctx context.Context, databaseURL string) error {
	conn, err := db.ConnectReplica(databaseURL)
	if err != nil {
		return fmt.Errorf("connect for auth-only purge: %w", err)
	}
	defer conn.Close()

	var authSchemaExists bool
	if err := conn.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='neon_auth')`).Scan(&authSchemaExists); err != nil {
		return fmt.Errorf("verify neon_auth schema: %w", err)
	}
	if !authSchemaExists {
		return fmt.Errorf("refusing purge: neon_auth schema was not found")
	}

	rows, err := conn.QueryContext(ctx, `SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename`)
	if err != nil {
		return fmt.Errorf("list public tables: %w", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("scan public table: %w", err)
		}
		tables = append(tables, name)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close public table rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate public tables: %w", err)
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin auth-only purge: %w", err)
	}
	defer tx.Rollback()
	for _, table := range tables {
		statement := `DROP TABLE IF EXISTS public.` + quotePostgresIdentifier(table) + ` CASCADE`
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("drop public table %s: %w", table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit auth-only purge: %w", err)
	}
	log.Printf("Neon auth-only purge complete: dropped %d public application tables; neon_auth schema preserved", len(tables))
	return nil
}

func quotePostgresIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}
