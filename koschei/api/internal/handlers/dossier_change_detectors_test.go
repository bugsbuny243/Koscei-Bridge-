package handlers

import "testing"

func dossierChangeFixture() map[string]any {
	return map[string]any{
		"target":       "Mint1111111111111111111111111111111111111",
		"generated_at": "2026-08-05T00:00:00Z",
		"modules": []any{
			map[string]any{
				"module_id": "token_authority_scanner", "evidence_status": "verified",
				"signals": map[string]any{"mint_authority_present": true, "freeze_authority_present": false},
			},
			map[string]any{
				"module_id": "holder_concentration", "evidence_status": "verified",
				"signals": map[string]any{
					"largest_holder_percentage": 31.0, "top_10_holder_percentage": 63.0,
					"token_supply": 1_050_000.0,
				},
			},
			map[string]any{
				"module_id": "sniper_timing_detector", "evidence_status": "observed",
				"signals": map[string]any{
					"failed_signature_count": 4, "recent_signature_count": 20,
					"signature_window_seconds": 600,
				},
			},
		},
		"structural_memory": map[string]any{
			"available": true,
			"has_authority_data": true,
			"mint_authority_present": false, "freeze_authority_present": false,
			"authority_observed_at": "2026-08-04T00:00:00Z",
			"has_holder_data": true,
			"largest_holder_percentage": 25.0, "top_10_holder_percentage": 60.0,
			"holder_observed_at": "2026-08-04T00:00:00Z",
			"token_supply": 1_000_000.0, "supply_observed_at": "2026-08-04T00:00:00Z",
		},
	}
}

func TestDerivedAuthorityChangeUsesPreviousVerifiedBaseline(t *testing.T) {
	report := dossierChangeFixture()
	def, _ := signalDefinitionByID("authority-change")
	state, raw := signalStateFor(report, def)
	if state != signalStateVerified {
		t.Fatalf("state=%q", state)
	}
	value := dossierMap(raw)
	if !dossierBool(value["changed"]) || !dossierBool(value["mint_authority_changed"]) || dossierBool(value["freeze_authority_changed"]) {
		t.Fatalf("value=%#v", value)
	}
}

func TestDerivedConcentrationAndSupplyChangesAreDeterministic(t *testing.T) {
	report := dossierChangeFixture()
	for _, id := range []string{"concentration-change", "supply-change"} {
		def, _ := signalDefinitionByID(id)
		firstState, firstRaw := signalStateFor(report, def)
		secondState, secondRaw := signalStateFor(report, def)
		if firstState != signalStateVerified || secondState != firstState {
			t.Fatalf("id=%s states=%q/%q", id, firstState, secondState)
		}
		if dossierString(dossierMap(firstRaw)["method"]) != dossierString(dossierMap(secondRaw)["method"]) {
			t.Fatalf("id=%s non-deterministic method", id)
		}
		if !dossierBool(dossierMap(firstRaw)["changed"]) {
			t.Fatalf("id=%s value=%#v", id, firstRaw)
		}
	}
}

func TestChangeRowsRemainWindowOpenWithoutBaseline(t *testing.T) {
	report := dossierChangeFixture()
	delete(report, "structural_memory")
	for _, id := range []string{"authority-change", "supply-change", "concentration-change"} {
		def, _ := signalDefinitionByID(id)
		state, _ := signalStateFor(report, def)
		if state != signalStateWindowOpen {
			t.Fatalf("id=%s state=%q", id, state)
		}
	}
}

func TestFailedAttemptWindowDoesNotClaimExploit(t *testing.T) {
	report := dossierChangeFixture()
	def, _ := signalDefinitionByID("exploit-attempts")
	state, raw := signalStateFor(report, def)
	if state != signalStateObserved {
		t.Fatalf("state=%q", state)
	}
	value := dossierMap(raw)
	if !dossierBool(value["repeated_failures_observed"]) {
		t.Fatalf("value=%#v", value)
	}
	if dossierString(value["grade_effect"]) != "none_v1" {
		t.Fatalf("grade_effect=%q", dossierString(value["grade_effect"]))
	}
}

func TestEvidenceReferenceRowsFollowRegistry(t *testing.T) {
	if len(unifiedVerdictCardRowIDs) != len(signalRegistry) {
		t.Fatalf("reference rows=%d registry=%d", len(unifiedVerdictCardRowIDs), len(signalRegistry))
	}
	for index, def := range signalRegistry {
		if unifiedVerdictCardRowIDs[index] != def.ID {
			t.Fatalf("index=%d refs=%q registry=%q", index, unifiedVerdictCardRowIDs[index], def.ID)
		}
	}
}
