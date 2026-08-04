package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Evidence-first publication policy. evaluateAutopublish is intentionally pure:
// it performs no I/O, reads no clock and inspects no mutable database state.
// Replaying the same immutable bundle, time and thresholds therefore yields the
// same decision, ordered reasons and policy identity.
const autopublishPolicyVersion = "koschei-autopublish-v1"

var (
	autopublishHashPattern          = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	autopublishSolanaAddressPattern = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`)
)

type autopublishThresholds struct {
	MinSignalRows   int
	MinVerifiedRows int
	MaxOpenRows     int
	MaxBlockedRows  int
	MaxUnknownRows  int
	MaxBundleAge    time.Duration
}

type autopublishCounts struct {
	SignalRows      int `json:"signal_rows"`
	Verified        int `json:"verified"`
	Observed        int `json:"observed"`
	Inferred        int `json:"inferred"`
	NotApplicable   int `json:"not_applicable"`
	WindowOpen      int `json:"window_open"`
	Pending         int `json:"pending"`
	NotInvestigated int `json:"not_investigated"`
	Unavailable     int `json:"unavailable"`
	Unknown         int `json:"unknown"`
	Open            int `json:"open"`
	Blocked         int `json:"blocked"`
}

type autopublishDecision struct {
	Publish       bool
	PolicyVersion string
	Reasons       []string
	Counts        autopublishCounts
	Thresholds    autopublishThresholds
	Title         string
	Summary       string
}

func defaultAutopublishThresholds() autopublishThresholds {
	return autopublishThresholds{
		MinSignalRows:   autopublishEnvInt("KOSCHEI_AUTOPUBLISH_MIN_SIGNAL_ROWS", 6, 1, 200),
		MinVerifiedRows: autopublishEnvInt("KOSCHEI_AUTOPUBLISH_MIN_VERIFIED_ROWS", 3, 1, 200),
		MaxOpenRows:     autopublishEnvInt("KOSCHEI_AUTOPUBLISH_MAX_OPEN_ROWS", 8, 0, 200),
		MaxBlockedRows:  autopublishEnvInt("KOSCHEI_AUTOPUBLISH_MAX_BLOCKED_ROWS", 2, 0, 200),
		MaxUnknownRows:  autopublishEnvInt("KOSCHEI_AUTOPUBLISH_MAX_UNKNOWN_ROWS", 0, 0, 200),
		MaxBundleAge: time.Duration(
			autopublishEnvInt("KOSCHEI_AUTOPUBLISH_MAX_BUNDLE_AGE_HOURS", 72, 1, 24*30),
		) * time.Hour,
	}
}

func countAutopublishSignalRows(bundle dossierBundle) autopublishCounts {
	card := dossierMap(bundle.VerdictCard)
	rows := dossierSlice(card["signal_rows"])
	counts := autopublishCounts{SignalRows: len(rows)}
	for _, raw := range rows {
		state := normalizeSignalState(dossierString(dossierMap(raw)["state"]))
		switch state {
		case signalStateVerified:
			counts.Verified++
		case signalStateObserved:
			counts.Observed++
		case signalStateInferred:
			counts.Inferred++
		case signalStateNotApplicable:
			counts.NotApplicable++
		case signalStateWindowOpen:
			counts.WindowOpen++
		case signalStatePending:
			counts.Pending++
		case signalStateNotInvestigated:
			counts.NotInvestigated++
		case signalStateUnavailable:
			counts.Unavailable++
		default:
			counts.Unknown++
		}
	}
	counts.Open = counts.WindowOpen + counts.Pending + counts.NotInvestigated
	counts.Blocked = counts.Unavailable + counts.Unknown
	return counts
}

func evaluateAutopublish(bundle dossierBundle, caseRef string, now time.Time, th autopublishThresholds) autopublishDecision {
	decision := autopublishDecision{
		Counts:        countAutopublishSignalRows(bundle),
		Thresholds:    th,
		PolicyVersion: th.policyVersion(),
	}
	reasons := map[string]struct{}{}
	add := func(reason string) { reasons[reason] = struct{}{} }

	storedCaseRef := strings.TrimSpace(caseRef)
	if !publicDossierCaseRefPattern.MatchString(storedCaseRef) {
		add("case_ref_invalid")
	}
	if bundle.CaseRef != storedCaseRef {
		add("case_ref_mismatch")
	}
	if !autopublishHashPattern.MatchString(strings.TrimSpace(bundle.BundleHash)) {
		add("bundle_hash_invalid")
	}
	if !autopublishHashPattern.MatchString(strings.TrimSpace(bundle.SourceSnapshotHash)) {
		add("source_snapshot_hash_invalid")
	}
	if bundle.ProducedAt.IsZero() {
		add("produced_at_missing")
	} else {
		if th.MaxBundleAge > 0 && now.Sub(bundle.ProducedAt) > th.MaxBundleAge {
			add("bundle_stale")
		}
		if bundle.ProducedAt.After(now.Add(5 * time.Minute)) {
			add("produced_at_in_future")
		}
	}

	target := dossierMap(bundle.Target)
	targetID := firstPublicDossierString(
		dossierString(target["id"]),
		dossierString(target["address"]),
		dossierString(target["mint"]),
	)
	if targetID == "" {
		add("target_id_missing")
	} else if !autopublishSolanaAddressPattern.MatchString(targetID) {
		add("target_id_invalid")
	}

	c := decision.Counts
	if c.SignalRows < th.MinSignalRows {
		add("signal_rows_below_minimum")
	}
	if c.Verified < th.MinVerifiedRows {
		add("verified_rows_below_minimum")
	}
	if c.Open > th.MaxOpenRows {
		add("open_rows_above_maximum")
	}
	if c.Blocked > th.MaxBlockedRows {
		add("blocked_rows_above_maximum")
	}
	if c.Unknown > th.MaxUnknownRows {
		add("unknown_state_rows_present")
	}

	verification := dossierMap(bundle.Verification)
	if len(verification) == 0 {
		add("verification_block_missing")
	}
	verdict := dossierMap(bundle.Verdict)
	if !dossierBool(verdict["signed"]) {
		add("final_verdict_unsigned")
	}
	verdictSignature := firstPublicDossierString(
		dossierString(verdict["signature"]),
		dossierString(verification["verdict_signature"]),
	)
	if verdictSignature == "" {
		add("verdict_signature_missing")
	}
	if len(bundle.Limitations) == 0 {
		add("limitations_missing")
	}

	decision.Reasons = sortedAutopublishReasons(reasons)
	decision.Publish = len(decision.Reasons) == 0
	if decision.Publish {
		decision.Title = defaultPublicDossierTitle(bundle)
		decision.Summary = defaultPublicDossierSummary(bundle)
	}
	return decision
}

func sortedAutopublishReasons(set map[string]struct{}) []string {
	if len(set) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(set))
	for reason := range set {
		out = append(out, reason)
	}
	sort.Strings(out)
	return out
}

func (th autopublishThresholds) policyVersion() string {
	canonical := fmt.Sprintf("signals=%d;verified=%d;open=%d;blocked=%d;unknown=%d;age_seconds=%d",
		th.MinSignalRows, th.MinVerifiedRows, th.MaxOpenRows, th.MaxBlockedRows,
		th.MaxUnknownRows, int64(th.MaxBundleAge/time.Second))
	sum := sha256.Sum256([]byte(canonical))
	return autopublishPolicyVersion + "+" + hex.EncodeToString(sum[:6])
}

func (th autopublishThresholds) asMap() map[string]any {
	return map[string]any{
		"min_signal_rows":      th.MinSignalRows,
		"min_verified_rows":    th.MinVerifiedRows,
		"max_open_rows":        th.MaxOpenRows,
		"max_blocked_rows":     th.MaxBlockedRows,
		"max_unknown_rows":     th.MaxUnknownRows,
		"max_bundle_age_hours": int(th.MaxBundleAge / time.Hour),
		"base_policy_version":  autopublishPolicyVersion,
		"policy_version":       th.policyVersion(),
	}
}

func autopublishEnvInt(key string, fallback, minimum, maximum int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}
