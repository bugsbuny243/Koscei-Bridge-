package handlers

import "testing"

func TestTrackRowCanReachVerifiedWithLifecycleReferences(t *testing.T) {
	report := map[string]any{
		"evidence_arms": []any{
			map[string]any{
				"module_id": "repeat_actor_scan",
				"signed":    true,
				"signature": "fixture-arm-signature",
				"signals": map[string]any{
					"creator_token_recurrence": true,
					"creator_other_mints":      []any{"fixture-other-mint"},
					"creator_creation_slots":   []any{int64(123)},
				},
			},
		},
		"evidence_references": map[string]any{
			"track": map[string]any{
				"wallets":    []any{"fixture-creator-wallet"},
				"accounts":   []any{"fixture-other-mint"},
				"signatures": []any{"fixture-creation-signature"},
				"slots":      []any{int64(123)},
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
