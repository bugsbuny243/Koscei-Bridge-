package handlers

import (
	"strings"
	"testing"
)

// Rule 1: one row, one source. Two rows sharing a source would present a single
// observation as several independent checks. The old card did exactly this:
// mint and freeze both read the authority arm with no field selector, and four
// rows shared launch_forensics.
func TestSignalRegistrySourcesAreUnique(t *testing.T) {
	seen := map[string]string{}
	for _, def := range signalRegistry {
		key := def.Source.signalSourceKey()
		if previous, exists := seen[key]; exists {
			t.Fatalf("rows %q and %q share source %q; one observation would render as two checks", previous, def.ID, key)
		}
		seen[key] = def.ID
	}
}

func TestSignalRegistryIDsAreUniqueAndLabelled(t *testing.T) {
	if len(signalRegistry) != 25 {
		t.Fatalf("registry has %d rows, want 25", len(signalRegistry))
	}
	seen := map[string]bool{}
	for _, def := range signalRegistry {
		if strings.TrimSpace(def.ID) == "" {
			t.Fatal("registry entry with empty id")
		}
		if seen[def.ID] {
			t.Fatalf("duplicate registry id %q", def.ID)
		}
		seen[def.ID] = true
		if strings.TrimSpace(def.Label) == "" {
			t.Fatalf("registry entry %q has no label", def.ID)
		}
		switch def.Source.Kind {
		case signalSourceModule, signalSourceBehavior, signalSourceReport:
		default:
			t.Fatalf("registry entry %q has unknown source kind %q", def.ID, def.Source.Kind)
		}
		if strings.TrimSpace(def.Source.Key) == "" {
			t.Fatalf("registry entry %q has no source key", def.ID)
		}
	}
}

// Rule 2: unknown resolves down. This is the regression that mattered most --
// the old dossierEvidenceState ended in `return "observed"`, so any status the
// switch did not recognize rendered as positive evidence on the customer card.
func TestNormalizeSignalStateFailsClosed(t *testing.T) {
	for _, raw := range []string{"partial", "maybe", "weird_new_status", "", "   ", "OBSERVED_ISH"} {
		if got := normalizeSignalState(raw); got != signalStateUnknown {
			t.Fatalf("status %q resolved to %q; unrecognized statuses must resolve to unknown", raw, got)
		}
	}
}

func TestNormalizeSignalStateKnownValues(t *testing.T) {
	cases := map[string]string{
		"verified":              signalStateVerified,
		"burned":                signalStateVerified,
		"observed":              signalStateObserved,
		"held_by_creator":       signalStateObserved,
		"inferred":              signalStateInferred,
		"not_applicable":        signalStateNotApplicable,
		"window_open":           signalStateWindowOpen,
		"arm_pending":           signalStatePending,
		"not_investigated":      signalStateNotInvestigated,
		"source_unavailable":    signalStateUnavailable,
		"requires_trade_ledger": signalStateUnavailable,
	}
	for raw, want := range cases {
		if got := normalizeSignalState(raw); got != want {
			t.Fatalf("status %q resolved to %q, want %q", raw, got, want)
		}
	}
}

// Rule 3: every state belongs to exactly one display group, and only evidence
// states count as evidence.
func TestSignalStateGroupsPartitionCleanly(t *testing.T) {
	all := []string{
		signalStateVerified, signalStateObserved, signalStateInferred,
		signalStateNotApplicable, signalStateWindowOpen, signalStatePending,
		signalStateNotInvestigated, signalStateUnavailable, signalStateUnknown,
	}
	groups := map[string]int{}
	for _, state := range all {
		groups[signalStateGroup(state)]++
	}
	if groups[signalGroupEvidence] != 2 {
		t.Fatalf("expected exactly verified and observed to be evidence, got %d", groups[signalGroupEvidence])
	}
	if groups[signalGroupOpen] != 3 {
		t.Fatalf("expected three open states, got %d", groups[signalGroupOpen])
	}
	for _, state := range all {
		isEvidence := signalStateIsEvidence(state)
		wantEvidence := state == signalStateVerified || state == signalStateObserved
		if isEvidence != wantEvidence {
			t.Fatalf("state %q evidence=%v, want %v", state, isEvidence, wantEvidence)
		}
	}
}

// An absent source means nothing was scheduled. Reporting it as pending would
// tell a reader a worker is running when none is.
func TestSignalStateForAbsentSourceIsNotInvestigated(t *testing.T) {
	report := map[string]any{}
	for _, def := range signalRegistry {
		state, _ := signalStateFor(report, def)
		if state != signalStateNotInvestigated {
			t.Fatalf("row %q on an empty report resolved to %q, want not_investigated", def.ID, state)
		}
	}
}

// Module lookup must be exact. Substring matching bound a row to whichever
// module happened to contain the needle first in the slice.
func TestResolveSignalSourceMatchesModuleExactly(t *testing.T) {
	report := map[string]any{
		"evidence_arms": []any{
			map[string]any{"module_id": "token_authority_scanner_legacy", "status": "verified"},
			map[string]any{"module_id": "token_authority_scanner", "status": "observed"},
		},
	}
	module, present := resolveSignalSource(report, signalSource{Kind: signalSourceModule, Key: "token_authority_scanner"})
	if !present {
		t.Fatal("expected exact module match")
	}
	if dossierString(module["status"]) != "observed" {
		t.Fatalf("matched the wrong module: %v", module)
	}
}

// Mint and freeze must be able to disagree. On the old card both read the same
// arm with no field selector, so a token with a revoked mint authority and a
// live freeze authority showed two identical rows.
func TestMintAndFreezeResolveIndependently(t *testing.T) {
	report := map[string]any{
		"evidence_arms": []any{
			map[string]any{
				"module_id":       "token_authority_scanner",
				"evidence_status": "observed",
				"signals": map[string]any{
					"mint_authority_present":   false,
					"freeze_authority_present": true,
				},
			},
		},
	}
	var mintValue, freezeValue any
	for _, def := range signalRegistry {
		state, value := signalStateFor(report, def)
		switch def.ID {
		case "mint":
			if state != signalStateObserved {
				t.Fatalf("mint state resolved to %q", state)
			}
			mintValue = value
		case "freeze":
			if state != signalStateObserved {
				t.Fatalf("freeze state resolved to %q", state)
			}
			freezeValue = value
		}
	}
	if mintValue != false || freezeValue != true {
		t.Fatalf("field selectors drifted: mint=%v freeze=%v", mintValue, freezeValue)
	}
}

// A source present but carrying no status at all must surface as unknown rather
// than be absorbed into a positive state.
func TestSignalStateForStatuslessSourceIsUnknown(t *testing.T) {
	report := map[string]any{
		"evidence_arms": []any{
			map[string]any{"module_id": "mev_shield", "note": "no status field"},
		},
	}
	for _, def := range signalRegistry {
		if def.ID != "mev" {
			continue
		}
		state, _ := signalStateFor(report, def)
		if state != signalStateUnknown {
			t.Fatalf("statusless source resolved to %q, want unknown", state)
		}
	}
}

// An arm that ran but never produced the narrowed field is a gap in the arm,
// distinct from a check that was never scheduled.
func TestSignalStateForMissingFieldIsUnavailable(t *testing.T) {
	report := map[string]any{
		"evidence_arms": []any{
			map[string]any{
				"module_id":       "token_authority_scanner",
				"evidence_status": "verified",
				"signals":         map[string]any{},
			},
		},
	}
	for _, def := range signalRegistry {
		if def.ID != "update-authority" {
			continue
		}
		state, _ := signalStateFor(report, def)
		if state != signalStateUnavailable {
			t.Fatalf("missing field resolved to %q, want unavailable", state)
		}
	}
}

// Every non-evidence state must explain itself on the row. A blank row that a
// reader interprets as a clean result is the failure this guards against.
func TestNonEvidenceRowsCarryLimitations(t *testing.T) {
	for _, state := range []string{
		signalStateNotApplicable, signalStateWindowOpen, signalStatePending,
		signalStateNotInvestigated, signalStateUnavailable, signalStateUnknown,
	} {
		if len(signalRowLimitations(state)) == 0 {
			t.Fatalf("state %q renders with no limitation text", state)
		}
	}
	for _, state := range []string{signalStateVerified, signalStateObserved} {
		if len(signalRowLimitations(state)) != 0 {
			t.Fatalf("evidence state %q should not carry a limitation", state)
		}
	}
}

// The ten detectors under discussion must each own a row, otherwise a detector
// can be implemented and still never reach the customer.
func TestRegistryCoversTheTenDetectors(t *testing.T) {
	required := []string{
		"authority-change", "supply-change", "liquidity", "creator-sell",
		"funding", "sniper", "concentration-change", "track",
		"program", "exploit-attempts",
	}
	present := map[string]bool{}
	for _, def := range signalRegistry {
		present[def.ID] = true
	}
	for _, id := range required {
		if !present[id] {
			t.Fatalf("detector row %q has no registry entry; it could never reach the card", id)
		}
	}
}

func TestBuildDossierSignalRowsRendersWholeRegistry(t *testing.T) {
	rows := buildDossierSignalRows(map[string]any{})
	if len(rows) != len(signalRegistry) {
		t.Fatalf("rendered %d rows for %d registry entries", len(rows), len(signalRegistry))
	}
	for i, row := range rows {
		if row.ID != signalRegistry[i].ID {
			t.Fatalf("row %d is %q, want %q; registry order must be stable", i, row.ID, signalRegistry[i].ID)
		}
	}
}
