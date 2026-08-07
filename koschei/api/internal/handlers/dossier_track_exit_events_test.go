package handlers

import "testing"

func TestTrackRowResolvesFromExitEventRecurrenceFixture(t *testing.T) {
	report := map[string]any{
		"evidence_arms": []any{
			map[string]any{
				"module_id": "repeat_actor_scan",
				"signals": map[string]any{
					"execution_status":                  "verified",
					"cross_token_exit_event_recurrence": true,
					"exit_event_actor_wallet":           "fixture-wallet",
					"exit_event_other_mints":            []any{"fixture-other-mint"},
					"exit_event_signatures":             []any{"fixture-event-signature"},
					"exit_event_slots":                  []any{int64(4242)},
				},
			},
		},
		"evidence_references": map[string]any{
			"track": map[string]any{
				"wallets":    []any{"fixture-wallet"},
				"accounts":   []any{"fixture-other-mint"},
				"signatures": []any{"fixture-event-signature"},
				"slots":      []any{int64(4242)},
			},
		},
	}
	rows := buildDossierSignalRows(report)
	for _, row := range rows {
		if row.ID != "track" {
			continue
		}
		if row.State != signalStateVerified {
			t.Fatalf("track state=%q want=%q", row.State, signalStateVerified)
		}
		if !dossierRefsPresent(row.Refs) || len(row.Refs.Wallets) != 1 || len(row.Refs.Accounts) != 1 || len(row.Refs.Signatures) != 1 || len(row.Refs.Slots) != 1 {
			t.Fatalf("track refs=%#v", row.Refs)
		}
		return
	}
	t.Fatal("track row missing")
}
