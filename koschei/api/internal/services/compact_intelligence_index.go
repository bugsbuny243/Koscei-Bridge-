package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/cache"
)

const (
	compactIntelligenceIndexVersion  = "koschei-compact-intelligence-index-v1"
	compactIntelligenceDefaultTTL    = 7 * 24 * time.Hour
	compactIntelligenceMaxTTL        = 30 * 24 * time.Hour
	compactTriggeredRuleLimit        = 16
	compactWatchFlagLimit            = 16
	compactDecisionPathLimit         = 16
	compactBehaviorSignalLimit       = 24
)

type CompactIntelligenceIndexRecord struct {
	Version             string                `json:"version"`
	Network             string                `json:"network"`
	TargetKind          string                `json:"target_kind"`
	TargetIDHash        string                `json:"target_id_hash"`
	Grade               string                `json:"grade"`
	Verdict             string                `json:"verdict"`
	RulesetVersion      string                `json:"ruleset_version"`
	ActorRulesetVersion string                `json:"actor_ruleset_version"`
	Signed              bool                  `json:"signed"`
	Fingerprint         string                `json:"fingerprint"`
	TriggeredRules      []ActorDefenseRuleHit `json:"triggered_rules"`
	WatchFlags          []ActorDefenseRuleHit `json:"watch_flags"`
	DecisionPath        []string              `json:"decision_path"`
	BehaviorSignals     []UnifiedRadarSignal  `json:"behavior_signals"`
	FirstSeenAt         time.Time             `json:"first_seen_at"`
	LastSeenAt          time.Time             `json:"last_seen_at"`
	ScanCount           int64                 `json:"scan_count"`
	TTLSeconds          int64                 `json:"ttl_seconds"`
}

func CompactIntelligenceIndexTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv("KOSCHEI_COMPACT_INDEX_TTL_HOURS"))
	if raw == "" {
		return compactIntelligenceDefaultTTL
	}
	hours, err := strconv.Atoi(raw)
	if err != nil || hours <= 0 {
		return compactIntelligenceDefaultTTL
	}
	ttl := time.Duration(hours) * time.Hour
	if ttl > compactIntelligenceMaxTTL {
		return compactIntelligenceMaxTTL
	}
	return ttl
}

func UpsertCompactIntelligenceIndex(ctx context.Context, c cache.Cache, network, targetKind, targetID string, verdict UnifiedRadarVerdict, behavior UnifiedRadarBehaviorReport) (CompactIntelligenceIndexRecord, string, error) {
	if c == nil {
		return CompactIntelligenceIndexRecord{}, "disabled", nil
	}
	if _, ok := c.(cache.Noop); ok {
		return CompactIntelligenceIndexRecord{}, "disabled", nil
	}
	network = normalizeRadarNetwork(network)
	targetKind = strings.TrimSpace(targetKind)
	targetID = strings.TrimSpace(targetID)
	if targetKind == "" || targetID == "" {
		return CompactIntelligenceIndexRecord{}, "invalid_target", fmt.Errorf("compact intelligence target is required")
	}

	fingerprint, err := UnifiedRadarVerdictFingerprint(network, targetKind, targetID, verdict, behavior)
	if err != nil {
		return CompactIntelligenceIndexRecord{}, "fingerprint_failed", err
	}
	now := verdict.GeneratedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	key, targetHash := compactIntelligenceIndexKey(network, targetKind, targetID)
	previous := CompactIntelligenceIndexRecord{}
	found, err := c.GetJSON(ctx, key, &previous)
	if err != nil {
		return CompactIntelligenceIndexRecord{}, "read_failed", err
	}
	firstSeen := now
	scanCount := int64(1)
	if found && previous.Version == compactIntelligenceIndexVersion {
		if !previous.FirstSeenAt.IsZero() {
			firstSeen = previous.FirstSeenAt.UTC()
		}
		if previous.ScanCount > 0 {
			scanCount = previous.ScanCount + 1
		}
	}
	ttl := CompactIntelligenceIndexTTL()
	record := CompactIntelligenceIndexRecord{
		Version:             compactIntelligenceIndexVersion,
		Network:             network,
		TargetKind:          targetKind,
		TargetIDHash:        targetHash,
		Grade:               normalizeUnifiedGrade(verdict.Grade),
		Verdict:             strings.TrimSpace(verdict.Verdict),
		RulesetVersion:      strings.TrimSpace(verdict.RulesetVersion),
		ActorRulesetVersion: strings.TrimSpace(verdict.ActorRuleset),
		Signed:              verdict.Signed,
		Fingerprint:         fingerprint,
		TriggeredRules:      compactActorRuleHits(verdict.TriggeredRules, compactTriggeredRuleLimit),
		WatchFlags:          compactActorRuleHits(verdict.WatchFlags, compactWatchFlagLimit),
		DecisionPath:        compactStrings(verdict.DecisionPath, compactDecisionPathLimit),
		BehaviorSignals:     compactUnifiedSignals(behavior.Signals, compactBehaviorSignalLimit),
		FirstSeenAt:         firstSeen,
		LastSeenAt:          now,
		ScanCount:           scanCount,
		TTLSeconds:          int64(ttl.Seconds()),
	}
	if err := c.SetJSON(ctx, key, record, ttl); err != nil {
		return CompactIntelligenceIndexRecord{}, "write_failed", err
	}
	if found {
		return record, "compact_index_updated", nil
	}
	return record, "compact_index_created", nil
}

func compactIntelligenceIndexKey(network, targetKind, targetID string) (string, string) {
	sum := sha256.Sum256([]byte(normalizeRadarNetwork(network) + "\x00" + strings.TrimSpace(targetKind) + "\x00" + strings.TrimSpace(targetID)))
	hash := hex.EncodeToString(sum[:])
	return "koschei:intel:index:v1:" + hash, hash
}

func compactActorRuleHits(input []ActorDefenseRuleHit, limit int) []ActorDefenseRuleHit {
	if limit <= 0 || len(input) == 0 {
		return []ActorDefenseRuleHit{}
	}
	if len(input) < limit {
		limit = len(input)
	}
	out := make([]ActorDefenseRuleHit, limit)
	copy(out, input[:limit])
	return out
}

func compactUnifiedSignals(input []UnifiedRadarSignal, limit int) []UnifiedRadarSignal {
	if limit <= 0 || len(input) == 0 {
		return []UnifiedRadarSignal{}
	}
	if len(input) < limit {
		limit = len(input)
	}
	out := make([]UnifiedRadarSignal, limit)
	copy(out, input[:limit])
	return out
}

func compactStrings(input []string, limit int) []string {
	if limit <= 0 || len(input) == 0 {
		return []string{}
	}
	if len(input) < limit {
		limit = len(input)
	}
	out := make([]string, limit)
	copy(out, input[:limit])
	return out
}
