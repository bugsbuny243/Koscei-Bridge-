package services

import (
	"context"
	"testing"
	"time"

	"koschei/api/internal/cache"
)

func TestCompactIntelligenceIndexCreatesAndUpdatesWithoutRawTargetKey(t *testing.T) {
	t.Setenv("KOSCHEI_COMPACT_INDEX_TTL_HOURS", "24")
	t.Setenv("KOSCHEI_COMPACT_INDEX_ALLOW_MEMORY", "true")
	ctx := context.Background()
	c := cache.NewMemory()
	defer c.Close()

	now := time.Date(2026, 9, 5, 6, 0, 0, 0, time.UTC)
	verdict := UnifiedRadarVerdict{
		Grade: "F", Verdict: "high_risk", RulesetVersion: "rules-v1", ActorRuleset: "actor-v1",
		TriggeredRules: []ActorDefenseRuleHit{{RuleID: "R-1"}},
		DecisionPath:   []string{"evidence", "rule", "verdict"}, GeneratedAt: now,
	}
	behavior := UnifiedRadarBehaviorReport{Signals: []UnifiedRadarSignal{{RuleID: "U-1", Triggered: true}}}

	first, status, err := UpsertCompactIntelligenceIndex(ctx, c, "solana-mainnet", "wallet", "CaseSensitiveWalletABC", verdict, behavior)
	if err != nil {
		t.Fatal(err)
	}
	if status != "compact_index_created" || first.ScanCount != 1 {
		t.Fatalf("status=%s record=%#v", status, first)
	}
	if first.TargetIDHash == "" || first.TargetIDHash == "CaseSensitiveWalletABC" {
		t.Fatalf("target hash=%q", first.TargetIDHash)
	}
	if first.TTLSeconds != 24*60*60 {
		t.Fatalf("ttl=%d", first.TTLSeconds)
	}

	verdict.GeneratedAt = now.Add(time.Hour)
	second, status, err := UpsertCompactIntelligenceIndex(ctx, c, "solana-mainnet", "wallet", "CaseSensitiveWalletABC", verdict, behavior)
	if err != nil {
		t.Fatal(err)
	}
	if status != "compact_index_updated" || second.ScanCount != 2 {
		t.Fatalf("status=%s record=%#v", status, second)
	}
	if !second.FirstSeenAt.Equal(first.FirstSeenAt) {
		t.Fatalf("first_seen changed: %s != %s", second.FirstSeenAt, first.FirstSeenAt)
	}
	if !second.LastSeenAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("last_seen=%s", second.LastSeenAt)
	}
}

func TestCompactIntelligenceIndexIsBounded(t *testing.T) {
	t.Setenv("KOSCHEI_COMPACT_INDEX_ALLOW_MEMORY", "true")
	ctx := context.Background()
	c := cache.NewMemory()
	defer c.Close()

	verdict := UnifiedRadarVerdict{Grade: "C", Verdict: "watch", GeneratedAt: time.Now().UTC()}
	for i := 0; i < 40; i++ {
		verdict.TriggeredRules = append(verdict.TriggeredRules, ActorDefenseRuleHit{RuleID: "R"})
		verdict.WatchFlags = append(verdict.WatchFlags, ActorDefenseRuleHit{RuleID: "W"})
		verdict.DecisionPath = append(verdict.DecisionPath, "step")
	}
	behavior := UnifiedRadarBehaviorReport{}
	for i := 0; i < 40; i++ {
		behavior.Signals = append(behavior.Signals, UnifiedRadarSignal{RuleID: "U"})
	}

	record, _, err := UpsertCompactIntelligenceIndex(ctx, c, "solana-mainnet", "token", "MintABC", verdict, behavior)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.TriggeredRules) != compactTriggeredRuleLimit || len(record.WatchFlags) != compactWatchFlagLimit {
		t.Fatalf("rules=%d watch=%d", len(record.TriggeredRules), len(record.WatchFlags))
	}
	if len(record.DecisionPath) != compactDecisionPathLimit || len(record.BehaviorSignals) != compactBehaviorSignalLimit {
		t.Fatalf("path=%d signals=%d", len(record.DecisionPath), len(record.BehaviorSignals))
	}
}

func TestCompactIntelligenceIndexMemoryDisabledByDefault(t *testing.T) {
	c := cache.NewMemory()
	defer c.Close()
	_, status, err := UpsertCompactIntelligenceIndex(context.Background(), c, "solana-mainnet", "wallet", "WalletABC", UnifiedRadarVerdict{}, UnifiedRadarBehaviorReport{})
	if err != nil {
		t.Fatal(err)
	}
	if status != "disabled" {
		t.Fatalf("status=%s", status)
	}
}

func TestCompactIntelligenceIndexNoopDoesNotClaimPersistence(t *testing.T) {
	_, status, err := UpsertCompactIntelligenceIndex(context.Background(), cache.NewNoop(), "solana-mainnet", "wallet", "WalletABC", UnifiedRadarVerdict{}, UnifiedRadarBehaviorReport{})
	if err != nil {
		t.Fatal(err)
	}
	if status != "disabled" {
		t.Fatalf("status=%s", status)
	}
}
