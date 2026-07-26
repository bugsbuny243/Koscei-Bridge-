package handlers

import (
	"context"
	"database/sql"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/services"
	"koschei/api/internal/workerwake"
)

type dueWatchlistTarget struct {
	ID          string
	AuthSubject string
}

// StartWatchlistMonitor turns the existing watchlist snapshot engine into
// continuous retail protection only when both automatic scanning and the
// watchlist worker are explicitly enabled. Manual refresh remains available.
func StartWatchlistMonitor(parent context.Context, db *sql.DB) func() {
	ctx, cancel := context.WithCancel(parent)
	if db == nil || !watchlistMonitorEnabled() {
		return cancel
	}
	interval := watchlistMonitorInterval()
	batchSize := watchlistMonitorBatchSize()
	h := &Handler{DB: db, DBRead: db}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		runWatchlistMonitorBatch(ctx, h, batchSize)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runWatchlistMonitorBatch(ctx, h, batchSize)
			}
		}
	}()
	log.Printf("watchlist monitor started: interval=%s batch=%d", interval, batchSize)
	return cancel
}

func runWatchlistMonitorBatch(ctx context.Context, h *Handler, limit int) {
	if h == nil || h.DB == nil || ctx.Err() != nil {
		return
	}
	targets, err := claimDueWatchlistTargets(ctx, h.DB, limit)
	if err != nil {
		if !isMissingRelation(err) {
			log.Printf("watchlist monitor claim failed: %v", err)
		}
		return
	}
	for _, target := range targets {
		if ctx.Err() != nil {
			return
		}
		_, alerts, err := h.refreshWatchlistTarget(ctx, target.AuthSubject, target.ID)
		if err != nil {
			log.Printf("watchlist monitor refresh failed id=%s: %v", target.ID, err)
			continue
		}
		if alerts > 0 {
			// watchlist_alerts has an AFTER INSERT trigger that queues webhook
			// deliveries. refreshWatchlistTarget returns only after its transaction
			// commits, so the trigger-created rows are visible before this wake.
			workerwake.Signal(workerwake.WebhookDelivery)
			log.Printf("watchlist monitor created alerts id=%s count=%d", target.ID, alerts)
		}
	}
}

func claimDueWatchlistTargets(ctx context.Context, db *sql.DB, limit int) ([]dueWatchlistTarget, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := db.QueryContext(ctx, `
		WITH due AS (
			SELECT id
			FROM watchlist_targets
			WHERE status='active' AND COALESCE(next_check_at,now())<=now()
			ORDER BY COALESCE(next_check_at,created_at) ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE watchlist_targets t
		SET next_check_at=now()+interval '5 minutes',updated_at=now()
		FROM due
		WHERE t.id=due.id
		RETURNING t.id::text,t.auth_subject`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]dueWatchlistTarget, 0, limit)
	for rows.Next() {
		var item dueWatchlistTarget
		if err := rows.Scan(&item.ID, &item.AuthSubject); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func watchlistMonitorEnabled() bool {
	if !services.AutomaticBackgroundScanningEnabled() {
		return false
	}
	value := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHLIST_MONITOR_ENABLED")))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func watchlistMonitorInterval() time.Duration {
	value := strings.TrimSpace(os.Getenv("WATCHLIST_MONITOR_INTERVAL"))
	if value == "" {
		return time.Minute
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < 15*time.Second {
		return time.Minute
	}
	return parsed
}

func watchlistMonitorBatchSize() int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv("WATCHLIST_MONITOR_BATCH_SIZE")))
	if err != nil || value <= 0 || value > 100 {
		return 20
	}
	return value
}
