package handlers

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestProductionSupportingEvidenceKeysBelongToDeclaredFile(t *testing.T) {
	root := filepath.Join("..", "..", "evidence", "production-full-scan")
	raw := readProductionEvidenceFile(t, filepath.Join(root, "2026-08-03-kosch.json"))

	var snapshot productionSnapshotFixture
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("decode production snapshot: %v", err)
	}
	if len(snapshot.Supporting) == 0 {
		t.Fatal("production snapshot has no supporting evidence groups")
	}

	for _, group := range snapshot.Supporting {
		if group.EvidenceFile == "" {
			t.Fatalf("supporting group %s has no declared evidence file", group.RuleID)
		}
		rows := readProductionEvidenceRows(t, filepath.Join(root, filepath.FromSlash(group.EvidenceFile)))
		fileKeys := make(map[string]bool, len(rows))
		for _, row := range rows {
			fileKeys[row.EvidenceKey] = true
		}
		for _, evidenceKey := range group.EvidenceKeys {
			if !fileKeys[evidenceKey] {
				t.Fatalf("%s declares evidence key %s that is not present in its own file", group.EvidenceFile, evidenceKey)
			}
		}
	}
}
