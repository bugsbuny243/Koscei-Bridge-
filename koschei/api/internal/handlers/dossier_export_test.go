package handlers

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func dossierTestReport() map[string]any {
	refs := map[string]any{}
	for _, def := range signalRegistry {
		value := map[string]any{
			"wallets": []string{}, "accounts": []string{"Mint111"}, "signatures": []string{},
			"slots": []int64{}, "evidence_keys": []string{"row:" + def.ID},
		}
		if def.ID == "concentration" {
			value["wallets"] = []string{"Owner111"}
		}
		if def.ID == "signed" {
			value["signatures"] = []string{"VerdictSignature111"}
		}
		refs[def.ID] = value
	}
	return map[string]any{
		"ok":             true,
		"schema_version": "koschei-unified-investigation-v1",
		"target":         "Mint111",
		"network":        "solana-mainnet",
		"generated_at":   "2026-07-17T08:00:00Z",
		"final_verdict": map[string]any{
			"grade": "F", "verdict": "hard_trigger", "signed": true,
			"signature": "VerdictSignature111", "ruleset_version": "koschei-unified-radar-rules-v1.1.0",
			"generated_at": "2026-07-17T08:00:00Z",
		},
		"threat_anticipation": map[string]any{"status": "observed", "pathways": []any{}},
		"holder_intelligence": map[string]any{
			"available": true, "owner_aggregation_applied": true, "circulating_supply": 1000000,
			"top_owner_percentage": 72.0,
		},
		"holder_concentration_context": map[string]any{
			"available": true, "top_share_pct": 72.0, "top_percentile": 5.0, "sample_count": 50000,
		},
		"launch_forensics": map[string]any{
			"available": true, "status": "observed", "launch_slot": 100, "creator_linked_count": 1,
		},
		"market":                  map[string]any{"available": true, "status": "verified_market_snapshot", "liquidity_usd": 100000.0},
		"lp_control":              map[string]any{"available": true, "status": "burned", "pool_address": "Pool111", "read_slot": 200},
		"source_context":          map[string]any{"creator_wallet": "Creator111"},
		"trade_ledger_aggregates": map[string]any{"available": true, "status": "observed", "trade_count": 3},
		"actor_investigation": map[string]any{
			"wallet": "Creator111", "store_status": "loaded",
			"integration_run": map[string]any{"status": "complete"},
		},
		"metadata_impersonation": map[string]any{"status": "not_applicable"},
		"modules": []any{
			map[string]any{
				"module_id": "token_authority_scanner", "evidence_status": "verified",
				"signals": map[string]any{
					"mint_authority_present": false, "freeze_authority_present": true, "update_authority_present": false,
				},
			},
			map[string]any{"module_id": "funding_cluster_detector", "evidence_status": "observed"},
			map[string]any{"module_id": "holder_concentration", "evidence_status": "observed"},
			map[string]any{"module_id": "sniper_timing_detector", "evidence_status": "observed"},
			map[string]any{"module_id": "launch_distribution", "evidence_status": "observed"},
			map[string]any{"module_id": "repeat_actor_scan", "evidence_status": "observed"},
			map[string]any{"module_id": "liquidity_movement", "evidence_status": "observed"},
			map[string]any{"module_id": "program_relation_scan", "evidence_status": "observed"},
			map[string]any{"module_id": "claim_surface_risk", "evidence_status": "not_applicable"},
			map[string]any{"module_id": "mev_shield", "evidence_status": "not_applicable"},
		},
		"evidence_arms": []any{},
		"behavior_signals": map[string]any{"signals": []any{
			map[string]any{"rule_id": "URD-C003", "evidence_status": "verified", "triggered": true},
			map[string]any{"rule_id": "URD-C004", "evidence_status": "verified", "triggered": true},
			map[string]any{"rule_id": "URD-C005", "evidence_status": "verified", "triggered": true},
		}},
		"transaction_evidence": []any{
			map[string]any{"signature": "TradeSig111", "slot": 300, "trader": "Owner111", "direction": "sell"},
		},
		"evidence_references": refs,
		"evidence_policy":     map[string]any{"no_evidence_no_claim": true},
	}
}

func dossierTestSnapshot(t *testing.T) dossierSnapshot {
	t.Helper()
	report := dossierTestReport()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return dossierSnapshot{
		ID:   "11111111-1111-4111-8111-111111111111",
		Mint: "Mint111", Network: "solana-mainnet",
		VerdictSignature: "VerdictSignature111",
		RulesetVersion:   "koschei-unified-radar-rules-v1.1.0",
		ProducedAt:       time.Date(2026, 7, 17, 8, 0, 0, 0, time.UTC),
		SourceHash:       dossierSHA256(raw), Report: report,
	}
}

func TestAssembleDossierBundleIsDeterministic(t *testing.T) {
	snapshot := dossierTestSnapshot(t)
	first, firstRaw, err := assembleDossierBundle(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	second, secondRaw, err := assembleDossierBundle(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstRaw) != string(secondRaw) {
		t.Fatal("identical snapshot produced different bytes")
	}
	if first.CaseRef != second.CaseRef || first.BundleHash != second.BundleHash {
		t.Fatal("deterministic identifiers changed")
	}
	if !strings.HasPrefix(first.CaseRef, "KD1-") || len(first.CaseRef) != 36 {
		t.Fatalf("case_ref=%q", first.CaseRef)
	}

	bodyRaw, err := json.Marshal(first.dossierBody)
	if err != nil {
		t.Fatal(err)
	}
	if first.BundleHash != dossierSHA256(bodyRaw) {
		t.Fatalf("bundle_hash=%q", first.BundleHash)
	}
	if first.SourceSnapshotHash != snapshot.SourceHash {
		t.Fatalf("source_hash=%q", first.SourceSnapshotHash)
	}

	card := dossierMap(first.VerdictCard)
	rows := dossierSlice(card["signal_rows"])
	if len(rows) != len(signalRegistry) {
		t.Fatalf("signal rows=%d registry=%d", len(rows), len(signalRegistry))
	}
	for _, item := range rows {
		row := dossierMap(item)
		state := dossierString(row["state"])
		def, registered := signalDefinitionByID(dossierString(row["id"]))
		refs := dossierMap(row["refs"])
		if registered && def.RequireRefs && signalStateIsEvidence(state) && len(refs) == 0 {
			t.Fatalf("row without refs: %#v", row)
		}
	}
	joined := strings.Join(first.Limitations, " ")
	for _, phrase := range []string{"Capability-not-intent", "Identity boundary", "Evidence-window boundary"} {
		if !strings.Contains(joined, phrase) {
			t.Fatalf("limitation %q missing", phrase)
		}
	}
}

func TestAssembleDossierBundleRejectsObservedRowWithoutRefs(t *testing.T) {
	snapshot := dossierTestSnapshot(t)
	refs := dossierMap(snapshot.Report["evidence_references"])
	refs["concentration"] = map[string]any{"wallets": []string{}, "accounts": []string{}, "signatures": []string{}, "slots": []int64{}, "evidence_keys": []string{}}
	_, _, err := assembleDossierBundle(snapshot)
	if !errors.Is(err, errDossierReferenceMissing) {
		t.Fatalf("err=%v", err)
	}
}

func TestDossierCaseRefDependsOnMintAndSignature(t *testing.T) {
	base := dossierCaseRef("Mint111", "Signature111")
	if base == dossierCaseRef("Mint222", "Signature111") {
		t.Fatal("mint did not affect case ref")
	}
	if base == dossierCaseRef("Mint111", "Signature222") {
		t.Fatal("signature did not affect case ref")
	}
	if base != dossierCaseRef(" Mint111 ", " Signature111 ") {
		t.Fatal("case ref normalization is unstable")
	}
}

func TestDossierBundleHashChangesWhenTechnicalReportChanges(t *testing.T) {
	firstSnapshot := dossierTestSnapshot(t)
	first, _, err := assembleDossierBundle(firstSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	secondSnapshot := dossierTestSnapshot(t)
	dossierMap(secondSnapshot.Report["market"])["liquidity_usd"] = 99999.0
	raw, _ := json.Marshal(secondSnapshot.Report)
	secondSnapshot.SourceHash = dossierSHA256(raw)
	second, _, err := assembleDossierBundle(secondSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if first.BundleHash == second.BundleHash {
		t.Fatal("technical report mutation did not change bundle hash")
	}
	if first.CaseRef != second.CaseRef {
		t.Fatal("same signed verdict changed case ref")
	}
}
