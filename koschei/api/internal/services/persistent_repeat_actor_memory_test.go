package services

import (
	"strings"
	"testing"
)

// ACTOR_INVESTIGATION_ENGINE.md sections 1, 2 and 6.
// Actor ruleset v1.0; unified Radar ruleset v1.0.
func TestEnsureCurrentPersistentDominantMatchAddsCurrentMintOnce(t *testing.T) {
	matches := []RepeatDominantHolderMatch{{Mint: "OldMint111", Percentage: 42, Rank: 2, ScannedAt: "2026-01-01T00:00:00Z"}}
	got := ensureCurrentPersistentDominantMatch(matches, "CurrentMint111", 55, 1)
	if len(got) != 2 {
		t.Fatalf("matches=%#v", got)
	}
	got = ensureCurrentPersistentDominantMatch(got, "CurrentMint111", 55, 1)
	if len(got) != 2 {
		t.Fatalf("current mint duplicated: %#v", got)
	}
}

func TestEnsureCurrentPersistentDominantMatchRejectsNonDominantCurrentMint(t *testing.T) {
	got := ensureCurrentPersistentDominantMatch(nil, "CurrentMint111", 19.99, 1)
	if len(got) != 0 {
		t.Fatalf("non-dominant current holder was added: %#v", got)
	}
}

func TestPersistentRepeatDominantEvidenceIsRetentionIndependentAndNoIdentityClaim(t *testing.T) {
	matches := []RepeatDominantHolderMatch{
		{Mint: "9cRCn9rGT8V2imeM2BaKs13yhMEais3ruM3rPvTGpump", Percentage: 58.71, Rank: 1, ScannedAt: "2025-01-12T10:00:00Z"},
		{Mint: "6QPvGr1L7aXGybpGKvvG8LtFDV9dRzK6QbSpRNJJonYM", Percentage: 78.67, Rank: 1, ScannedAt: "2026-07-13T10:00:00Z"},
	}
	line := PersistentRepeatDominantEvidenceLine("GV6UUmNxxVdC52", matches)
	for _, expected := range []string{"kalıcı actor index", "2 farklı token", "ham-event retention", "ortak kimlik veya niyet iddiası değildir"} {
		if !strings.Contains(line, expected) {
			t.Fatalf("missing %q: %s", expected, line)
		}
	}
	if strings.Contains(line, "son 30 gün") {
		t.Fatalf("persistent evidence regressed to bounded window: %s", line)
	}
}

func TestPersistentRepeatActorNoMatchCompletesAllTimeQueryWithoutSafetyClaim(t *testing.T) {
	t.Setenv("SOLANA_RPC_URL", "")
	req := SecurityRadarRequest{Target: "MintPersistentRepeat1111111111111111111111111", Network: "solana-mainnet", Mode: "manual_test"}
	analysis := AnalyzeArvisRadars(req)
	analysis = ApplyPersistentRepeatDominantHolderEvidenceToAnalysis(analysis, req, nil)
	for _, arm := range analysis.Arms {
		if arm.ModuleID != ModuleRepeatActorScan {
			continue
		}
		if !arm.Signed || arvisSignalString(arm.Signals, "execution_status") != ArvisExecutionCompleted {
			t.Fatalf("repeat arm=%#v", arm)
		}
		if got := arvisSignalString(arm.Signals, "memory_scope"); got != "persistent_actor_index_all_time" {
			t.Fatalf("memory_scope=%q", got)
		}
		if bounded, ok := arm.Signals["bounded_window"].(bool); !ok || bounded {
			t.Fatalf("bounded_window=%#v", arm.Signals["bounded_window"])
		}
		joined := strings.Join(arm.Evidence, " ") + " " + arm.Verdict + " " + arm.Recommendation
		if strings.Contains(joined, "30-day") || strings.Contains(joined, "30 gün") {
			t.Fatalf("all-time query still claims 30-day scope: %s", joined)
		}
		if !strings.Contains(joined, "not a safety claim") {
			t.Fatalf("negative finding lacks safety limitation: %s", joined)
		}
		return
	}
	t.Fatal("repeat actor arm missing")
}
