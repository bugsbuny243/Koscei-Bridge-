package handlers

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/services"
)

func (h *Handler) analyzeLaunchForensics(parent context.Context, target string, roles services.HolderRoleAnalysis, cluster services.HolderClusterAnalysis, source map[string]any) services.LaunchForensicsAnalysis {
	rpcURL := strings.TrimSpace(firstNonEmptyString(os.Getenv("SOLANA_RPC_URL"), os.Getenv("ALCHEMY_SOLANA_RPC_URL"), os.Getenv("HELIUS_SOLANA_RPC_URL")))
	creator := strings.TrimSpace(creatorIntelCleanString(source["creator_wallet"]))
	launchBlockTime, launchSlot, anchorSource := resolveLaunchForensicsAnchor(source, cluster)
	timeout := 120 * time.Second
	if raw := strings.TrimSpace(os.Getenv("ARVIS_FORENSICS_TIMEOUT_SECONDS")); raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil && seconds >= 30 && seconds <= 300 {
			timeout = time.Duration(seconds) * time.Second
		}
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	result := services.AnalyzeLaunchForensics(ctx, h.launchForensicsDB(), rpcURL, target, creator, roles, launchBlockTime, launchSlot)
	if anchorSource != "" && result.LaunchSlot == launchSlot && launchSlot > 0 {
		result.LaunchTimeSource = anchorSource
	}
	return result
}

// resolveLaunchForensicsAnchor keeps sniper timing tied to the token's verified
// creation event when the canonical source context has one. Pool migration or
// cluster activity can be useful secondary context, but a later pool/cluster
// estimate must never redefine token creation and manufacture negative
// "minutes from launch" values for transactions that happened after creation.
func resolveLaunchForensicsAnchor(source map[string]any, cluster services.HolderClusterAnalysis) (int64, int64, string) {
	clusterTime := int64(0)
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(cluster.LaunchEstimateAt)); err == nil {
		clusterTime = parsed.Unix()
	}
	clusterSlot := cluster.LaunchEstimateSlot

	canonical := map[string]any{}
	if raw, ok := source["canonical_creator_verification"].(map[string]any); ok && raw != nil {
		canonical = raw
	}
	canonicalVerified, _ := canonical["verified"].(bool)
	canonicalSlot := creatorIntelInt64(canonical["slot"])
	if canonicalSlot <= 0 {
		canonicalSlot = creatorIntelInt64(source["slot"])
	}
	sourceVerified, _ := source["creator_relation_verified"].(bool)
	if canonicalVerified || sourceVerified {
		if canonicalSlot > 0 {
			if blockTime := canonicalLaunchBlockTime(source); blockTime > 0 {
				return blockTime, canonicalSlot, "verified_canonical_create_transaction"
			}
			return 0, canonicalSlot, "verified_canonical_create_slot"
		}
	}

	if clusterSlot > 0 || clusterTime > 0 {
		return clusterTime, clusterSlot, "cluster_launch_estimate"
	}
	if eventType := strings.ToLower(strings.TrimSpace(creatorIntelCleanString(source["event_type"]))); strings.Contains(eventType, "new_token") || strings.Contains(eventType, "launch") {
		if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(creatorIntelCleanString(source["observed_at"]))); err == nil {
			return parsed.Unix(), creatorIntelInt64(source["slot"]), "source_launch_event"
		}
	}
	return 0, 0, ""
}

func canonicalLaunchBlockTime(source map[string]any) int64 {
	for _, raw := range []any{source["observed_at"], source["created_at"]} {
		if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(creatorIntelCleanString(raw))); err == nil {
			return parsed.Unix()
		}
	}
	if resolution, ok := source["creator_resolution"].(map[string]any); ok {
		for _, raw := range []any{resolution["created_at"], resolution["first_mint_at"]} {
			if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(creatorIntelCleanString(raw))); err == nil {
				return parsed.Unix()
			}
		}
		for _, raw := range []any{resolution["created_time"], resolution["first_mint_time"]} {
			if value := creatorIntelInt64(raw); value > 0 {
				return value
			}
		}
	}
	if value := creatorIntelInt64(source["created_time"]); value > 0 {
		return value
	}
	return 0
}

func (h *Handler) launchForensicsDB() *sql.DB {
	if h == nil {
		return nil
	}
	// Live Pump trades are written to the primary database and can be newer than
	// a read replica. Prefer the primary so a scan performed seconds after launch
	// sees the ledger immediately; fall back to DBRead only when necessary.
	if h.DB != nil {
		return h.DB
	}
	return h.DBRead
}
