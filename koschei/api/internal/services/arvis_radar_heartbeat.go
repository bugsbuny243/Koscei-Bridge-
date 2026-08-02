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

const (
	defaultRaydiumProgramID  = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"
	legacyRaydiumProgramID   = "675kPX9MHTjS2zt1qfr1NYhd1B9M9QGK6cEcDDCo2t9"
	legacyRaydiumSourceID    = "675kPX9MHTjS2zt1qfr1NY5Wwrzj4mWjU7VtXv9syS2"
	defaultPumpProgramID     = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
	defaultPumpSwapProgramID = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"
)

type arvisHeartbeatSource struct {
	Label     string
	ProgramID string
	ModuleID  string
	EventType string
}

func StartArvisRadarHeartbeat(ctx context.Context, db *sql.DB) func() {
	if db == nil || envBool("ARVIS_HEARTBEAT_DISABLED") {
		return func() {}
	}
	rpcURL := firstSecurityRadarEnv("SOLANA_RPC_URL", "ALCHEMY_SOLANA_RPC_URL", "HELIUS_SOLANA_RPC_URL", "QUICKNODE_SOLANA_RPC_URL")
	if rpcURL == "" {
		if key := strings.TrimSpace(os.Getenv("ALCHEMY_API_KEY")); key != "" {
			rpcURL = "https://solana-mainnet.g.alchemy.com/v2/" + key
		}
	}
	if rpcURL == "" {
		rpcURL = defaultSolanaMainnetRPC
	}
	ctx, cancel := context.WithCancel(ctx)
	go arvisRadarHeartbeatLoop(ctx, NewSecurityRadarStore(db), rpcURL)
	return cancel
}

func arvisRadarHeartbeatLoop(ctx context.Context, store *SecurityRadarStore, rpcURL string) {
	pollEvery := 60 * time.Second
	if raw := strings.TrimSpace(os.Getenv("ARVIS_HEARTBEAT_SECONDS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 30 && n <= 300 {
			pollEvery = time.Duration(n) * time.Second
		}
	}
	sources := arvisHeartbeatSources()
	log.Printf("arvis radar heartbeat started interval=%s sources=%d", pollEvery, len(sources))
	arvisRadarHeartbeatOnce(ctx, store, rpcURL)
	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("arvis radar heartbeat stopped")
			return
		case <-ticker.C:
			arvisRadarHeartbeatOnce(ctx, store, rpcURL)
		}
	}
}

func arvisHeartbeatSources() []arvisHeartbeatSource {
	return []arvisHeartbeatSource{
		{
			Label:     "raydium_program",
			ProgramID: normalizeRaydiumProgramID(os.Getenv("RAYDIUM_PROGRAM_ID")),
			ModuleID:  ModuleRaydiumPoolGuardian,
			EventType: "raydium_program_signature",
		},
		{
			Label:     "pump_program",
			ProgramID: firstRadarValue(os.Getenv("PUMP_FUN_PROGRAM_ID"), defaultPumpProgramID),
			ModuleID:  ModulePumpSybilRadar,
			EventType: "pump_program_signature",
		},
		{
			Label:     "pumpswap_program",
			ProgramID: firstRadarValue(os.Getenv("PUMP_SWAP_PROGRAM_ID"), defaultPumpSwapProgramID),
			ModuleID:  ModulePumpSybilRadar,
			EventType: "pumpswap_program_signature",
		},
	}
}

func normalizeRaydiumProgramID(value string) string {
	value = strings.TrimSpace(value)
	switch value {
	case "", legacyRaydiumProgramID, legacyRaydiumSourceID:
		return defaultRaydiumProgramID
	default:
		return value
	}
}

func arvisRadarHeartbeatOnce(ctx context.Context, store *SecurityRadarStore, rpcURL string) {
	if store == nil || store.DB == nil || strings.TrimSpace(rpcURL) == "" {
		return
	}
	for _, source := range arvisHeartbeatSources() {
		if strings.TrimSpace(source.ProgramID) == "" {
			continue
		}
		arvisPollHeartbeatSource(ctx, store, rpcURL, source)
	}
}

func arvisPollHeartbeatSource(ctx context.Context, store *SecurityRadarStore, rpcURL string, source arvisHeartbeatSource) {
	pollCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	signatures, err := SolanaGetSignaturesForAddress(pollCtx, rpcURL, source.ProgramID, 3)
	cancel()
	if err != nil {
		log.Printf("arvis radar heartbeat poll failed source=%s: %s", source.Label, safeProviderError(err))
		return
	}
	for i := len(signatures) - 1; i >= 0; i-- {
		info := signatures[i]
		sig := strings.TrimSpace(info.Signature)
		if sig == "" || arvisHeartbeatEventExists(ctx, store.DB, sig, source.ProgramID) {
			continue
		}

		target := ""
		targetType := "program"
		evidenceQuality := "live_program_signature"
		decoded := map[string]any{
			"source":     source.Label,
			"module_id":  source.ModuleID,
			"program_id": source.ProgramID,
			"rpc_method": "getSignaturesForAddress",
		}
		txCtx, txCancel := context.WithTimeout(ctx, 7*time.Second)
		tx, txErr := SolanaGetTransactionJSONParsed(txCtx, rpcURL, sig)
		txCancel()
		if txErr == nil {
			mints := extractMintsFromTransactionMap(map[string]any(tx))
			selectedMint := selectArvisTargetMint(mints)
			decoded["enriched_mints"] = mints
			decoded["selected_project_mint"] = selectedMint
			decoded["base_asset_mints_filtered"] = selectedMint != "" && len(mints) > 1
			decoded["transaction_parsed"] = true
			if selectedMint != "" {
				target = selectedMint
				targetType = "token"
				evidenceQuality = "transaction_enriched_mint"
				decoded["enriched_mint"] = target
			}
		} else {
			decoded["transaction_parsed"] = false
			decoded["enrichment_error"] = compactRadarError("getTransaction", txErr)
		}

		_, err := store.InsertStreamEvent(ctx, SecurityRadarStreamEventRecord{
			Provider:        "solana_rpc",
			StreamMode:      "heartbeat_poll",
			Network:         "solana-mainnet",
			ModuleID:        source.ModuleID,
			EventType:       source.EventType,
			Target:          target,
			TargetType:      targetType,
			Signature:       sig,
			Slot:            info.Slot,
			ProgramID:       source.ProgramID,
			EvidenceQuality: evidenceQuality,
			Decoded:         decoded,
			RawEvent: map[string]any{
				"signature": sig,
				"slot":      info.Slot,
				"target":    target,
				"source":    source.Label,
			},
		})
		if err != nil {
			log.Printf("arvis radar heartbeat insert failed source=%s: %v", source.Label, err)
		}
	}
}

func arvisHeartbeatEventExists(ctx context.Context, db *sql.DB, signature, programID string) bool {
	if db == nil || strings.TrimSpace(signature) == "" || strings.TrimSpace(programID) == "" {
		return false
	}
	var exists bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM security_radar_stream_events
			WHERE signature=$1
			  AND stream_mode='heartbeat_poll'
			  AND program_id=$2
		)
	`, signature, programID).Scan(&exists)
	return err == nil && exists
}
