// Package workerwake provides event-driven wake-up for the canonical job,
// webhook delivery and security alert workers.
//
// PostgreSQL LISTEN/NOTIFY is deliberately not used. A persistent listener
// connection would work against the scale-to-zero objective. Producers and
// consumers in the API process share coalescing in-memory gates; a bounded
// recovery ceiling covers process restarts and work inserted by another
// instance.
package workerwake

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Canonical gate names. Producers and consumers must agree on these values.
const (
	WebhookDelivery        = "webhook-delivery"
	SecurityAlertDelivery  = "security-alert-delivery"
	CanonicalInvestigation = "canonical-investigation-job"
)

const (
	minRecoveryCeiling     = time.Minute
	maxRecoveryCeiling     = time.Hour
	defaultRecoveryCeiling = 15 * time.Minute
)

// Gate is a coalescing wake channel for one worker loop.
type Gate struct {
	ch chan struct{}
}

func NewGate() *Gate {
	return &Gate{ch: make(chan struct{}, 1)}
}

// Signal never blocks. Multiple enqueues coalesce because workers drain their
// queues after waking.
func (g *Gate) Signal() {
	if g == nil {
		return
	}
	select {
	case g.ch <- struct{}{}:
	default:
	}
}

// Wait blocks until a signal, timeout or cancellation. A non-positive sleep
// falls back to the recovery ceiling instead of creating a hot loop.
func (g *Gate) Wait(ctx context.Context, sleep time.Duration) bool {
	if g == nil {
		return false
	}
	ceiling := RecoveryCeiling()
	if sleep <= 0 || sleep > ceiling {
		sleep = ceiling
	}
	timer := time.NewTimer(sleep)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-g.ch:
		return true
	case <-timer.C:
		return false
	}
}

// Drain clears one pending signal without blocking.
func (g *Gate) Drain() {
	if g == nil {
		return
	}
	select {
	case <-g.ch:
	default:
	}
}

var (
	registryMu sync.Mutex
	registry   = map[string]*Gate{}
)

func Get(name string) *Gate {
	name = strings.TrimSpace(name)
	registryMu.Lock()
	defer registryMu.Unlock()
	gate, ok := registry[name]
	if !ok {
		gate = NewGate()
		registry[name] = gate
	}
	return gate
}

func Signal(name string) {
	Get(name).Signal()
}

// RecoveryCeiling is the longest a worker sleeps without a recovery probe.
// The configured value is clamped so a typo cannot recreate high-frequency
// polling or leave missed work parked indefinitely.
func RecoveryCeiling() time.Duration {
	raw := strings.TrimSpace(os.Getenv("KOSCHEI_WORKER_RECOVERY_CEILING_SECONDS"))
	if raw == "" {
		return defaultRecoveryCeiling
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil {
		return defaultRecoveryCeiling
	}
	value := time.Duration(seconds) * time.Second
	if value < minRecoveryCeiling {
		return minRecoveryCeiling
	}
	if value > maxRecoveryCeiling {
		return maxRecoveryCeiling
	}
	return value
}

// NextDueSleep asks the database once, when a delivery worker becomes idle,
// how long remains until its next retry. Queue names map to fixed SQL; no table
// or predicate is accepted from callers.
func NextDueSleep(ctx context.Context, db *sql.DB, queueName string) time.Duration {
	if db == nil {
		return RecoveryCeiling()
	}
	query, ok := dueQuery(queueName)
	if !ok {
		return RecoveryCeiling()
	}
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var seconds sql.NullFloat64
	if err := db.QueryRowContext(queryCtx, query).Scan(&seconds); err != nil || !seconds.Valid {
		return RecoveryCeiling()
	}
	if seconds.Float64 <= 0 {
		return 0
	}
	return time.Duration(seconds.Float64 * float64(time.Second))
}

func dueQuery(queueName string) (string, bool) {
	switch strings.TrimSpace(queueName) {
	case WebhookDelivery:
		// Paused endpoints are excluded. Otherwise a due row belonging to a
		// paused endpoint would make NextDueSleep return zero forever while the
		// claim query correctly refuses to claim it.
		return `
			SELECT EXTRACT(EPOCH FROM (MIN(d.next_attempt_at) - now()))
			FROM webhook_deliveries d
			JOIN webhook_endpoints e ON e.id=d.endpoint_id
			WHERE d.status IN ('pending','retry')
			  AND e.status='active'`, true
	case SecurityAlertDelivery:
		return `
			SELECT EXTRACT(EPOCH FROM (MIN(next_attempt_at) - now()))
			FROM security_alert_deliveries
			WHERE status IN ('pending','retry')`, true
	default:
		return "", false
	}
}
