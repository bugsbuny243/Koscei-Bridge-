package handlers

import (
	"context"
	"database/sql"
	"strings"
)

// classifyActorWalletTarget preserves the strict RPC-first target boundary. It
// falls back only when RPC classification is unavailable and the exact target
// already exists as a wallet track in Koschei's persistent actor index.
func classifyActorWalletTarget(ctx context.Context, db *sql.DB, target, network string) radarTargetClassification {
	classification := classifyRadarTarget(ctx, target)
	if classification.Type == radarTargetWallet || classification.Type == radarTargetTokenAccount {
		return classification
	}
	if db == nil || !actorWalletPersistentFallbackEligible(classification) || !actorWalletBase58Address(target) {
		return classification
	}

	var state string
	err := db.QueryRowContext(ctx, `
		SELECT state
		FROM security_threat_tracks
		WHERE network=$1 AND target_kind='wallet' AND target_id=$2
		LIMIT 1`, strings.TrimSpace(network), strings.TrimSpace(target)).Scan(&state)
	if err != nil {
		return classification
	}
	resolved, ok := actorWalletPersistentClassification(classification, target, state)
	if !ok {
		return classification
	}
	return resolved
}

func actorWalletPersistentClassification(classification radarTargetClassification, target, state string) (radarTargetClassification, bool) {
	if !actorWalletPersistentFallbackEligible(classification) || !actorWalletBase58Address(target) || !actorWalletPersistentState(state) {
		return classification, false
	}
	originalEvidence := strings.TrimSpace(classification.Evidence)
	classification.Type = radarTargetWallet
	classification.Status = "verified_persistent_actor_index"
	classification.AccountOwner = ""
	classification.TokenOwnerWallet = ""
	classification.ParsedType = ""
	classification.Executable = false
	classification.Evidence = "Exact target is recorded as target_kind=wallet in the persistent actor index. Live RPC account classification was unavailable; persisted evidence is used without claiming a refreshed account state."
	if originalEvidence != "" {
		classification.Evidence += " RPC limitation: " + originalEvidence
	}
	return classification, true
}

func actorWalletPersistentFallbackEligible(classification radarTargetClassification) bool {
	if classification.Type != radarTargetUnknown {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(classification.Status)) {
	case "lookup_failed", "rpc_unavailable":
		return true
	default:
		return false
	}
}

func actorWalletPersistentState(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "detected", "tracked", "correlated", "verified", "alerted":
		return true
	default:
		return false
	}
}

func actorWalletBase58Address(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 32 || len(value) > 44 {
		return false
	}
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	for _, char := range value {
		if !strings.ContainsRune(alphabet, char) {
			return false
		}
	}
	return true
}
