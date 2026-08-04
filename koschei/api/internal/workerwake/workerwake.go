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

const (
	WebhookDelivery        = "webhook-delivery"
	SecurityAlertDelivery  = "security-alert-delivery"
	CanonicalInvestigation = "canonical-investigation-job"
	DossierAutopublish     = "dossier-autopublish"
)

const (
	minRecoveryCeiling     = time.Minute
	maxRecoveryCeiling     = time.Hour
	defaultRecoveryCeiling = 15 * time.Minute
)

type Gate struct {
	ch chan struct{}
}

func NewGate() *Gate {
	return &Gate{ch: make(chan struct{}, 1)}
}

func (g *Gate) Signal() {
	if g == nil {
		return
	}
	select {
	case g.ch <- struct{}{}:
	default:
	}
}

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
