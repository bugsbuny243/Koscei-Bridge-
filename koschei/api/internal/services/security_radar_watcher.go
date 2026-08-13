package services

import (
	"context"
	"database/sql"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/web3"
)

func SecurityRadarAutoEnabled() bool {
	if !AutomaticBackgroundScanningEnabled() {
		return false
	}
	if OwnerUnlimitedAutomaticScanningEnabled() {
		return true
	}
	value := strings.TrimSpace(os.Getenv("KOSCHEI_AUTO_RADAR_ENABLED"))
	return strings.EqualFold(value, "1") || strings.EqualFold(value, "true")
}

func StartSecurityRadarWatcher(ctx context.Context, db *sql.DB, _ *web3.SolanaRPC) func() {
	if db == nil {
		return func() {}
	}
	// Retention and corpus aggregation are pure database hygiene. They stay
	// active even when every quota-consuming automatic scanner is disabled.
	stopRetention := StartSecurityRadarRetentionWorkerV2(ctx, db)
	stopCorpus := StartHolderConcentrationCorpusWorker(ctx, db)
	stopDatabaseWorkers := func() {
		stopCorpus()
		stopRetention()
	}
	if !AutomaticBackgroundScanningEnabled() {
		log.Printf("security radar automatic workers disabled by KOSCHEI_AUTOMATIC_SCANNING_ENABLED")
		return stopDatabaseWorkers
	}
	if SolanaRPCLimitSaverEnabled() && !ForceBackgroundRadarEnabled() {
		log.Printf("broad security radar RPC workers paused: SOLANA_RPC_LIMIT_SAVER_ENABLED=true; manual scans remain available")
		return stopDatabaseWorkers
	}
	stopHeartbeat := StartArvisRadarHeartbeat(ctx, db)
	// Stream observations are evidence/trigger inputs only. The retired stream
	// verdict worker attempted to manufacture a final_verdict_engine arm even
	// though ARVIS arms are evidence-only. Route those observations into the
	// canonical investigation worker instead.
	stopStreamCanonicalBridge := StartArvisStreamCanonicalBridge(ctx, db)
	stopStreamRecovery := StartArvisStreamRecovery(ctx, db)
	stopGapHealer := StartSecurityRadarGapHealerIfEnabled(ctx, db)
	stopAll := func() {
		stopGapHealer()
		stopStreamRecovery()
		stopStreamCanonicalBridge()
		stopHeartbeat()
		stopDatabaseWorkers()
	}
	if !SecurityRadarAutoEnabled() {
		return stopAll
	}
	rpcURL := firstSecurityRadarEnv("SOLANA_RPC_URL", "ALCHEMY_SOLANA_RPC_URL")
	if rpcURL == "" {
		log.Printf("security radar polling worker not started: SOLANA_RPC_URL is empty")
		return stopAll
	}
	pollEvery := 10 * time.Minute
	if raw := strings.TrimSpace(os.Getenv("KOSCHEI_RADAR_POLL_SECONDS")); raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil && seconds >= 300 && seconds <= 3600 {
			pollEvery = time.Duration(seconds) * time.Second
		}
	}
	worker := NewSecurityRadarWorker(NewSecurityRadarStore(db), rpcURL, true, pollEvery)
	pollCtx, cancelPolling := context.WithCancel(ctx)
	go worker.Start(pollCtx)
	return func() {
		cancelPolling()
		stopAll()
	}
}

func firstSecurityRadarEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}
