package services

import (
	"context"
	"database/sql"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type PumpPortalRadarAdapter struct {
	Store *SecurityRadarStore
	queue chan PumpPortalEvent
}

func NewPumpPortalRadarAdapter(store *SecurityRadarStore) *PumpPortalRadarAdapter {
	return &PumpPortalRadarAdapter{Store: store, queue: make(chan PumpPortalEvent, 2048)}
}

func (a *PumpPortalRadarAdapter) Start(ctx context.Context) {
	if a == nil || a.Store == nil || a.Store.DB == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-a.queue:
			if err := a.HandleEvent(ctx, event); err != nil && ctx.Err() == nil {
				log.Printf("pumpportal radar event failed: %v", err)
			}
		}
	}
}

// Enqueue remains for compatibility with tests/older callers. Production
// discovery uses PumpPortalDurableInbox and does not route new-token coverage
// through this lossy bounded channel.
func (a *PumpPortalRadarAdapter) Enqueue(event PumpPortalEvent) bool {
	if a == nil || a.queue == nil {
		return false
	}
	select {
	case a.queue <- event:
		return true
	default:
		log.Printf("pumpportal legacy radar queue full; event not accepted mint=%s", resolvePumpPortalMint(event))
		return false
	}
}

func (a *PumpPortalRadarAdapter) HandleEvent(ctx context.Context, ev PumpPortalEvent) error {
	if a == nil || a.Store == nil || a.Store.DB == nil {
		return nil
	}
	mint := resolvePumpPortalMint(ev)
	if mint == "" {
		return nil
	}
	signature := strings.TrimSpace(ev.Signature)
	creator := strings.TrimSpace(ev.Creator)
	eventType := pumpPortalEventType(ev)
	signals := pumpPortalSignals(ev, mint, signature, eventType)
	rawSummary := map[string]any{
		"source":      "pumpportal",
		"event_type":  eventType,
		"mint":        mint,
		"name":        ev.Name,
		"symbol":      ev.Symbol,
		"creator":     creator,
		"trader":      ev.Trader,
		"tx_type":     ev.TxType,
		"signature":   signature,
		"received_at": ev.ReceivedAt,
		"raw":         ev.Raw,
	}
	_, err := a.Store.InsertEvent(ctx, SecurityRadarEventRecord{
		ModuleID:      ModulePumpSybilRadar,
		Target:        mint,
		TargetType:    "token",
		Network:       "solana-mainnet",
		Signature:     signature,
		SourceAddress: firstNonEmptyPumpPortal(creator, ev.Trader),
		EventType:     eventType,
		Signals:       signals,
		RawSummary:    rawSummary,
		Source:        "pumpportal",
	})
	if err != nil {
		return err
	}

	// The durable radar event is the commit point. Marking the signature before
	// InsertEvent could turn a transient DB failure into permanent data loss:
	// the retry would see the signature and skip an event that never committed.
	if signature != "" {
		if _, err := a.Store.MarkSignatureSeen(ctx, ModulePumpSybilRadar, signature, firstNonEmptyPumpPortal(creator, ev.Trader), "solana-mainnet"); err != nil {
			return err
		}
	}

	// Discovery is intentionally cheap. PumpPortal new-token/migration events are
	// stored for coverage; the selective 24h volume scheduler decides which mint
	// may consume RPC through the canonical investigation job worker.
	return nil
}

func pumpPortalSignals(ev PumpPortalEvent, mint, signature, eventType string) map[string]any {
	creator := strings.TrimSpace(ev.Creator)
	signals := map[string]any{
		"source":                     "pumpportal",
		"provider":                   "pumpportal",
		"event_type":                 eventType,
		"launch_platform":            "pump.fun",
		"mint":                       mint,
		"name":                       ev.Name,
		"token_name":                 ev.Name,
		"symbol":                     ev.Symbol,
		"token_symbol":               ev.Symbol,
		"creator":                    creator,
		"trader":                     ev.Trader,
		"tx_type":                    ev.TxType,
		"signature":                  signature,
		"received_at":                ev.ReceivedAt,
		"creator_identity_claimed":   false,
		"creator_relation_scope":     "source-reported launch metadata",
		"customer_detail_visible":    true,
		"source_verified_pump_event": true,
	}
	if isLikelySolanaAddress(creator) {
		signals["creator_wallet"] = creator
		signals["deployer_wallet"] = creator
		signals["creator_wallet_source"] = "pumpportal_event_metadata"
	}
	return signals
}

func pumpPortalArmVerified(arm SecurityRadarVerdict) bool {
	if !arm.Signed || arm.Signals == nil {
		return false
	}
	for _, key := range []string{"verified_evidence", "real_onchain_evidence", "real_offchain_evidence"} {
		if value, _ := arm.Signals[key].(bool); value {
			return true
		}
	}
	return false
}

func pumpPortalWarningLabel(risk int) string {
	switch {
	case risk >= 65:
		return "HIGH_RISK_WARNING"
	case risk >= 35:
		return "WARNING"
	default:
		return "MONITOR"
	}
}

func StartPumpPortalRadarIfEnabled(ctx context.Context, db *sql.DB) func() {
	cfg := LoadPumpPortalConfigFromEnv()
	volumeEnabled := PumpHighVolumeRadarEnabled()
	if !cfg.Enabled && !volumeEnabled {
		return func() {}
	}
	if db == nil {
		log.Printf("pump selective radar disabled: database unavailable")
		return func() {}
	}
	workerCtx, cancel := context.WithCancel(ctx)
	store := NewSecurityRadarStore(db)
	if cfg.Enabled {
		adapter := NewPumpPortalRadarAdapter(store)
		inbox := NewPumpPortalDurableInbox(db, adapter)
		ledger := NewPumpTradeLedgerWriter(db)
		client := NewPumpPortalClient(cfg)
		go inbox.Start(workerCtx)
		go ledger.Start(workerCtx)
		go client.Start(workerCtx, func(eventCtx context.Context, event PumpPortalEvent) error {
			ledger.EnqueuePumpPortal(event)
			if !isPumpPortalTradeEvent(event) {
				return inbox.PersistDiscovery(eventCtx, event)
			}
			return nil
		})
		log.Printf("pumpportal discovery + durable inbox + non-blocking trade ledger started websocket=%s", cfg.redactedWebsocketHost())
	}
	if volumeEnabled {
		if canonicalInvestigationWorkerActive() {
			log.Printf("legacy inline pump high-volume scanner paused: canonical investigation job scheduler owns selective deep scans")
		} else {
			worker := NewPumpHighVolumeRadarWorker(store, nil)
			go worker.Start(workerCtx)
			log.Printf("pump selective automatic radar started: volume_window=24h currency=USD threshold=%.0f poll=%s max_reports_per_cycle=%d rpc_saver=%t", worker.ThresholdUSD, worker.PollEvery, worker.MaxReportsPerCycle, SolanaRPCLimitSaverEnabled())
		}
	}
	return cancel
}

func canonicalInvestigationWorkerActive() bool {
	if raw := strings.TrimSpace(os.Getenv("KOSCHEI_CANONICAL_JOB_WORKER_ENABLED")); raw != "" {
		value, err := strconv.ParseBool(raw)
		return err == nil && value
	}
	return strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production")
}

func resolvePumpPortalMint(ev PumpPortalEvent) string {
	for _, candidate := range []string{ev.Mint, ev.TokenMint} {
		candidate = strings.TrimSpace(candidate)
		if isLikelySolanaAddress(candidate) {
			return candidate
		}
	}
	if ev.Raw != nil {
		for _, key := range []string{"mint", "tokenMint", "ca", "address"} {
			if value, ok := ev.Raw[key].(string); ok && isLikelySolanaAddress(value) {
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}

func pumpPortalEventType(ev PumpPortalEvent) string {
	value := strings.ToLower(strings.TrimSpace(firstNonEmptyPumpPortal(ev.Type, ev.TxType)))
	if strings.Contains(value, "migrat") {
		return "pumpportal_migration"
	}
	return "pumpportal_new_token"
}

func mergePumpPortalSignals(base map[string]any, extra map[string]any) map[string]any {
	if base == nil {
		base = map[string]any{}
	}
	for k, v := range extra {
		if s, ok := v.(string); ok && strings.TrimSpace(s) == "" {
			continue
		}
		base[k] = v
	}
	base["pumpportal_discovered_at"] = time.Now().UTC()
	return base
}

func firstNonEmptyPumpPortal(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
