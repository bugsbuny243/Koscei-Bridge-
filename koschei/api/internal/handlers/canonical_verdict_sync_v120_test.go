package handlers

import (
	"strings"
	"testing"

	"koschei/api/internal/services"
)

func TestCanonicalVerdictSynchronizationPreservesSignedV120HardCap(t *testing.T) {
	current := services.UnifiedRadarVerdict{
		Grade:          "D",
		Verdict:        "hard_trigger",
		RulesetVersion: services.UnifiedRadarRulesetVersionV120,
		ActorRuleset:   services.ActorDefenseRulesetVersion,
		TriggeredRules: []services.ActorDefenseRuleHit{
			{
				RuleID:         services.UnifiedRuleCrossTokenCreatorHolderTransfer,
				Title:          "Cross-token creator to dominant-holder transfer",
				Tier:           "compounding",
				EvidenceStatus: "verified",
				GradeEffect:    "hard_cap_D",
				EvidenceKeys:   []string{"creator-holder-transfer:signature"},
				Signatures:     []string{"signature"},
			},
		},
		Signed:    true,
		Signature: "koschei-unified:existing-v120",
	}
	report := map[string]any{
		"target":        "MintV120",
		"final_verdict": current,
	}

	final, ok := synchronizeCanonicalUnifiedVerdict(report)
	if !ok {
		t.Fatal("signed v1.2 verdict was not synchronized")
	}
	if final.Grade != "D" || final.Verdict != "hard_trigger" {
		t.Fatalf("v1.2 hard cap changed: %#v", final)
	}
	if final.RulesetVersion != services.UnifiedRadarRulesetVersionV120 {
		t.Fatalf("v1.2 ruleset downgraded: %q", final.RulesetVersion)
	}
	if !final.Signed || !strings.HasPrefix(final.Signature, "koschei-unified:") {
		t.Fatalf("v1.2 verdict was not normalized and target-bound: %#v", final)
	}
}

func TestCanonicalUnifiedRulesetVersionComparison(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{version: services.UnifiedRadarRulesetVersionV120, want: true},
		{version: "koschei-unified-radar-rules-v1.10.0", want: true},
		{version: services.UnifiedRadarRulesetVersionV110, want: false},
		{version: "invalid", want: false},
	}
	for _, tc := range cases {
		if got := canonicalUnifiedRulesetAtLeast(tc.version, 1, 2, 0); got != tc.want {
			t.Fatalf("canonicalUnifiedRulesetAtLeast(%q)=%t want %t", tc.version, got, tc.want)
		}
	}
}
