package handlers

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

const testAutopublishCaseRef = "KD1-d3zbkastatbvgxmg3cixjxwtu3ektlnt"

func testAutopublishThresholds() autopublishThresholds {
	return autopublishThresholds{
		MinSignalRows:   6,
		MinVerifiedRows: 3,
		MaxOpenRows:     8,
		MaxBlockedRows:  2,
		MaxUnknownRows:  0,
		MaxBundleAge:    72 * time.Hour,
	}
}

func signalRows(states map[string]int) any {
	rows := []any{}
	ordered := []string{
		signalStateVerified, signalStateObserved, signalStateInferred,
		signalStateNotApplicable, signalStateWindowOpen, signalStatePending,
		signalStateNotInvestigated, signalStateUnavailable, signalStateUnknown,
	}
	for _, state := range ordered {
		for i := 0; i < states[state]; i++ {
			rows = append(rows, map[string]any{"id": state, "state": state})
		}
	}
	return map[string]any{"signal_rows": rows}
}

func passingBundle(now time.Time) dossierBundle {
	verdictSignature := "koschei-unified:" + strings.Repeat("c", 64)
	return dossierBundle{
		dossierBody: dossierBody{
			CaseRef:            testAutopublishCaseRef,
			ProducedAt:         now.Add(-time.Hour),
			SourceSnapshotHash: "sha256:" + strings.Repeat("a", 64),
			Target:             map[string]any{"kind": "wallet", "id": "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe"},
			Verdict:            map[string]any{"signed": true, "signature": verdictSignature, "grade": "D"},
			VerdictCard: signalRows(map[string]int{
				signalStateVerified:        5,
				signalStateObserved:        3,
				signalStateInferred:        2,
				signalStateNotApplicable:   2,
				signalStateNotInvestigated: 4,
				signalStateUnavailable:     1,
			}),
			Verification: map[string]any{"verdict_signature": verdictSignature},
			Limitations:  dossierLimitations,
		},
		BundleHash: "sha256:" + strings.Repeat("b", 64),
	}
}

func hasReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

func TestAutopublishAcceptsCompleteBundle(t *testing.T) {
	now := time.Date(2026, 8, 4, 7, 0, 0, 0, time.UTC)
	decision := evaluateAutopublish(passingBundle(now), testAutopublishCaseRef, now, testAutopublishThresholds())
	if !decision.Publish {
		t.Fatalf("expected publish, withheld with reasons %v", decision.Reasons)
	}
	if len(decision.Reasons) != 0 || decision.Title == "" || decision.Summary == "" {
		t.Fatalf("invalid published decision: %+v", decision)
	}
	if decision.Counts.Verified != 5 || decision.Counts.Open != 4 || decision.Counts.Blocked != 1 {
		t.Fatalf("unexpected counts %+v", decision.Counts)
	}
	if !strings.HasPrefix(decision.PolicyVersion, autopublishPolicyVersion+"+") {
		t.Fatalf("threshold fingerprint missing from policy version %q", decision.PolicyVersion)
	}
}

func TestAutopublishWithholdsUnknownRowsEvenInsideBlockedBudget(t *testing.T) {
	now := time.Date(2026, 8, 4, 7, 0, 0, 0, time.UTC)
	bundle := passingBundle(now)
	bundle.VerdictCard = signalRows(map[string]int{
		signalStateVerified: 3,
		signalStateObserved: 3,
		signalStateUnknown:  1,
	})
	decision := evaluateAutopublish(bundle, testAutopublishCaseRef, now, testAutopublishThresholds())
	if decision.Publish || !hasReason(decision.Reasons, "unknown_state_rows_present") {
		t.Fatalf("unknown row must withhold: %+v", decision)
	}
	if decision.Counts.Unknown != 1 || decision.Counts.Blocked != 1 {
		t.Fatalf("unexpected counts %+v", decision.Counts)
	}
}

func TestAutopublishOpenAndBlockedThresholdsAreSeparate(t *testing.T) {
	now := time.Date(2026, 8, 4, 7, 0, 0, 0, time.UTC)
	bundle := passingBundle(now)
	bundle.VerdictCard = signalRows(map[string]int{
		signalStateVerified:        3,
		signalStateObserved:        3,
		signalStateNotInvestigated: 9,
		signalStateUnavailable:     3,
	})
	decision := evaluateAutopublish(bundle, testAutopublishCaseRef, now, testAutopublishThresholds())
	for _, reason := range []string{"open_rows_above_maximum", "blocked_rows_above_maximum"} {
		if !hasReason(decision.Reasons, reason) {
			t.Fatalf("missing %s in %v", reason, decision.Reasons)
		}
	}
}

func TestAutopublishWithholdsStaleAndFutureBundles(t *testing.T) {
	now := time.Date(2026, 8, 4, 7, 0, 0, 0, time.UTC)
	stale := passingBundle(now)
	stale.ProducedAt = now.Add(-8 * 24 * time.Hour)
	if decision := evaluateAutopublish(stale, testAutopublishCaseRef, now, testAutopublishThresholds()); !hasReason(decision.Reasons, "bundle_stale") {
		t.Fatalf("expected bundle_stale, got %v", decision.Reasons)
	}
	future := passingBundle(now)
	future.ProducedAt = now.Add(2 * time.Hour)
	if decision := evaluateAutopublish(future, testAutopublishCaseRef, now, testAutopublishThresholds()); !hasReason(decision.Reasons, "produced_at_in_future") {
		t.Fatalf("expected produced_at_in_future, got %v", decision.Reasons)
	}
}

func TestAutopublishIntegrityGates(t *testing.T) {
	now := time.Date(2026, 8, 4, 7, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*dossierBundle)
		reason string
	}{
		{"case mismatch", func(b *dossierBundle) { b.CaseRef = "KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }, "case_ref_mismatch"},
		{"bundle hash", func(b *dossierBundle) { b.BundleHash = "sha256:zzzz" }, "bundle_hash_invalid"},
		{"source hash", func(b *dossierBundle) { b.SourceSnapshotHash = "" }, "source_snapshot_hash_invalid"},
		{"target missing", func(b *dossierBundle) { b.Target = map[string]any{"kind": "wallet"} }, "target_id_missing"},
		{"target invalid", func(b *dossierBundle) { b.Target = map[string]any{"id": "not-solana"} }, "target_id_invalid"},
		{"verification", func(b *dossierBundle) { b.Verification = nil }, "verification_block_missing"},
		{"unsigned", func(b *dossierBundle) { b.Verdict = map[string]any{"signed": false, "signature": "x"} }, "final_verdict_unsigned"},
		{"signature", func(b *dossierBundle) { b.Verdict = map[string]any{"signed": true}; b.Verification = map[string]any{} }, "verdict_signature_missing"},
		{"limitations", func(b *dossierBundle) { b.Limitations = nil }, "limitations_missing"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle := passingBundle(now)
			tc.mutate(&bundle)
			decision := evaluateAutopublish(bundle, testAutopublishCaseRef, now, testAutopublishThresholds())
			if decision.Publish || !hasReason(decision.Reasons, tc.reason) {
				t.Fatalf("expected %s, got %+v", tc.reason, decision)
			}
		})
	}
}

func TestAutopublishWithholdsThinOrEmptyCard(t *testing.T) {
	now := time.Date(2026, 8, 4, 7, 0, 0, 0, time.UTC)
	thin := passingBundle(now)
	thin.VerdictCard = signalRows(map[string]int{signalStateVerified: 3})
	if decision := evaluateAutopublish(thin, testAutopublishCaseRef, now, testAutopublishThresholds()); !hasReason(decision.Reasons, "signal_rows_below_minimum") {
		t.Fatalf("expected thin-card reason, got %v", decision.Reasons)
	}
	empty := passingBundle(now)
	empty.VerdictCard = nil
	decision := evaluateAutopublish(empty, testAutopublishCaseRef, now, testAutopublishThresholds())
	if decision.Publish || decision.Counts.SignalRows != 0 {
		t.Fatalf("empty card passed: %+v", decision)
	}
}

func TestAutopublishReasonsAndPolicyIdentityAreDeterministic(t *testing.T) {
	now := time.Date(2026, 8, 4, 7, 0, 0, 0, time.UTC)
	bundle := passingBundle(now)
	bundle.VerdictCard = signalRows(map[string]int{signalStateUnknown: 9})
	bundle.Verification = nil
	bundle.Limitations = nil
	first := evaluateAutopublish(bundle, testAutopublishCaseRef, now, testAutopublishThresholds())
	for i := 0; i < 50; i++ {
		next := evaluateAutopublish(bundle, testAutopublishCaseRef, now, testAutopublishThresholds())
		if !reflect.DeepEqual(next.Reasons, first.Reasons) || next.PolicyVersion != first.PolicyVersion {
			t.Fatalf("decision drifted: %+v vs %+v", first, next)
		}
	}
}

func TestAutopublishThresholdChangeChangesPolicyVersion(t *testing.T) {
	base := testAutopublishThresholds()
	changed := base
	changed.MaxOpenRows++
	if base.policyVersion() == changed.policyVersion() {
		t.Fatal("threshold changes must produce a new decision identity")
	}
}

func TestAutopublishEnvIntClamps(t *testing.T) {
	t.Setenv("KOSCHEI_AUTOPUBLISH_MIN_VERIFIED_ROWS", "-5")
	if got := autopublishEnvInt("KOSCHEI_AUTOPUBLISH_MIN_VERIFIED_ROWS", 3, 1, 200); got != 1 {
		t.Fatalf("expected clamp to 1, got %d", got)
	}
	t.Setenv("KOSCHEI_AUTOPUBLISH_MIN_VERIFIED_ROWS", "not-a-number")
	if got := autopublishEnvInt("KOSCHEI_AUTOPUBLISH_MIN_VERIFIED_ROWS", 3, 1, 200); got != 3 {
		t.Fatalf("expected fallback to 3, got %d", got)
	}
}

func TestAutopublishDisabledByDefault(t *testing.T) {
	t.Setenv("KOSCHEI_AUTOPUBLISH_ENABLED", "")
	t.Setenv("APP_ENV", "production")
	if AutopublishWorkerEnabled() {
		t.Fatal("autopublish must stay off until explicitly enabled")
	}
}
