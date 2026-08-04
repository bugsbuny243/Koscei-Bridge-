package handlers

import (
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestBuildPublicRadarLiveEventsFiltersToRecentSignedLetterGrades(t *testing.T) {
	now := time.Date(2026, 8, 4, 7, 30, 0, 0, time.UTC)
	base := services.SecurityRadarVerdictRecord{
		ModuleID:  services.ModuleFinalVerdictEngine,
		Target:    "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdCsvHcx6PRe",
		TargetType: "token_mint",
		Network:   "solana-mainnet",
		Signed:    true,
		Signature: "signed-verdict",
		Signals:   map[string]any{"verified_evidence": true},
		CreatedAt: now.Add(-10 * time.Minute),
	}

	validF := base
	validF.ID = "f"
	validF.Grade = "F"
	validF.RiskIndex = 91
	validF.RiskLevel = "critical"

	validB := base
	validB.ID = "b"
	validB.Grade = "b"
	validB.RiskIndex = 31
	validB.RiskLevel = "medium"
	validB.CreatedAt = now.Add(-2 * time.Minute)
	validB.Signals = map[string]any{"real_onchain_evidence": true}

	withhold := base
	withhold.ID = "withhold"
	withhold.Grade = "WITHHOLD"

	old := base
	old.ID = "old"
	old.Grade = "A"
	old.CreatedAt = now.Add(-25 * time.Hour)

	hidden := base
	hidden.ID = "hidden"
	hidden.Grade = "D"
	hidden.Signals = map[string]any{"verified_evidence": true, "customer_detail_visible": false}

	unsigned := base
	unsigned.ID = "unsigned"
	unsigned.Grade = "A"
	unsigned.Signed = false

	events := buildPublicRadarLiveEvents([]services.SecurityRadarVerdictRecord{
		validF, withhold, old, hidden, unsigned, validB,
	}, now)

	if len(events) != 2 {
		t.Fatalf("expected 2 public live events, got %d: %#v", len(events), events)
	}
	if events[0].ID != "b" || events[0].Grade != "B" {
		t.Fatalf("expected newest normalized B result first, got %#v", events[0])
	}
	if events[1].ID != "f" || events[1].Grade != "F" {
		t.Fatalf("expected F result second, got %#v", events[1])
	}
	if events[0].Target == validB.Target {
		t.Fatalf("raw target must not be exposed on public live feed")
	}
}

func TestPublicRadarLetterGradeRejectsWithhold(t *testing.T) {
	for _, grade := range []string{"A", "b", " C ", "D", "f"} {
		if _, ok := publicRadarLetterGrade(grade); !ok {
			t.Fatalf("expected %q to be accepted", grade)
		}
	}
	for _, grade := range []string{"", "-", "WITHHOLD", "E", "SAFE"} {
		if _, ok := publicRadarLetterGrade(grade); ok {
			t.Fatalf("expected %q to be rejected", grade)
		}
	}
}
