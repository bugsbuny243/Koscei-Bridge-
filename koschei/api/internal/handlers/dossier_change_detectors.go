package handlers

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"
)

const dossierChangeBaselineMaxAge = 7 * 24 * time.Hour

// derivedDossierSignalSource turns already-collected immutable report evidence
// into customer-facing change rows. It performs no I/O and never treats a
// missing baseline as proof that no change occurred.
func derivedDossierSignalSource(report map[string]any, rowID string) (map[string]any, bool) {
	switch strings.TrimSpace(rowID) {
	case "authority-change":
		return deriveAuthorityChange(report), true
	case "supply-change":
		return deriveSupplyChange(report), true
	case "concentration-change":
		return deriveConcentrationChange(report), true
	case "exploit-attempts":
		return deriveFailedAttemptWindow(report), true
	default:
		return nil, false
	}
}

func deriveAuthorityChange(report map[string]any) map[string]any {
	arm := dossierChangeModule(report, "token_authority_scanner")
	current := dossierMap(arm["signals"])
	mint, mintOK := dossierChangeBool(current["mint_authority_present"])
	freeze, freezeOK := dossierChangeBool(current["freeze_authority_present"])
	if len(arm) == 0 {
		return dossierChangeNotInvestigated("Token Authority Scanner did not produce a source row.")
	}
	if !signalStateIsEvidence(normalizeSignalState(firstNonEmptyString(
		dossierString(arm["evidence_status"]), dossierString(arm["status"]),
	))) {
		return dossierChangeUnavailable("Current token-authority evidence is unavailable.")
	}
	if !mintOK || !freezeOK {
		return dossierChangeUnavailable("Current authority capability flags are incomplete.")
	}

	baseline := dossierMap(report["structural_memory"])
	if !dossierBool(baseline["has_authority_data"]) || !dossierChangeBaselineFresh(report, baseline, "authority_observed_at") {
		return map[string]any{
			"status": "monitoring_window_active", "evidence_status": "window_open",
			"current":     map[string]any{"mint_authority_present": mint, "freeze_authority_present": freeze},
			"changed":     nil,
			"method":      "compare_current_verified_capability_flags_to_previous_verified_structural_memory",
			"limitations": []string{"A fresh previous verified authority observation is required before a change can be asserted."},
		}
	}
	previousMint, previousMintOK := dossierChangeBool(baseline["mint_authority_present"])
	previousFreeze, previousFreezeOK := dossierChangeBool(baseline["freeze_authority_present"])
	if !previousMintOK || !previousFreezeOK {
		return dossierChangeUnavailable("Previous structural authority flags are incomplete.")
	}
	mintChanged := mint != previousMint
	freezeChanged := freeze != previousFreeze
	return map[string]any{
		"status": "verified", "evidence_status": "verified",
		"changed":                mintChanged || freezeChanged,
		"mint_authority_changed": mintChanged, "freeze_authority_changed": freezeChanged,
		"previous":             map[string]any{"mint_authority_present": previousMint, "freeze_authority_present": previousFreeze},
		"current":              map[string]any{"mint_authority_present": mint, "freeze_authority_present": freeze},
		"baseline_observed_at": baseline["authority_observed_at"],
		"current_observed_at":  report["generated_at"],
		"method":               "compare_current_verified_capability_flags_to_previous_verified_structural_memory",
		"grade_effect":         "none_v1",
		"limitations":          []string{"This detects capability-state transitions only; it does not identify the authority signer or prove intent."},
	}
}

func deriveSupplyChange(report map[string]any) map[string]any {
	arm := dossierChangeModule(report, "holder_concentration")
	currentSignals := dossierMap(arm["signals"])
	current, currentOK := dossierChangeFloat(currentSignals["token_supply"])
	if len(arm) == 0 {
		return dossierChangeNotInvestigated("Holder Concentration did not produce a source row for supply monitoring.")
	}
	if !currentOK || current < 0 {
		return dossierChangeUnavailable("Current parsed token supply is unavailable.")
	}
	baseline := dossierMap(report["structural_memory"])
	previous, previousOK := dossierChangeFloat(baseline["token_supply"])
	if !dossierBool(baseline["has_supply_data"]) || !previousOK || previous < 0 || !dossierChangeBaselineFresh(report, baseline, "supply_observed_at") {
		return map[string]any{
			"status": "monitoring_window_active", "evidence_status": "window_open",
			"current_supply": current, "previous_supply": nil, "growth": nil,
			"method":      "compare_parsed_token_supply_across_verified_observations",
			"limitations": []string{"The current supply was observed, but no fresh compatible previous supply baseline exists yet."},
		}
	}
	delta := current - previous
	growth := delta > 0
	percent := 0.0
	if previous > 0 {
		percent = delta / previous * 100
	}
	return map[string]any{
		"status": "verified", "evidence_status": "verified",
		"growth": growth, "changed": delta != 0,
		"previous_supply": previous, "current_supply": current,
		"delta": dossierChangeRound(delta), "delta_percent": dossierChangeRound(percent),
		"baseline_observed_at": baseline["supply_observed_at"],
		"current_observed_at":  report["generated_at"],
		"method":               "compare_parsed_token_supply_across_verified_observations",
		"grade_effect":         "none_v1",
		"limitations":          []string{"Supply growth is an on-chain capability event; it is not by itself proof of malicious intent."},
	}
}

func deriveConcentrationChange(report map[string]any) map[string]any {
	arm := dossierChangeModule(report, "holder_concentration")
	currentSignals := dossierMap(arm["signals"])
	currentTop1, top1OK := dossierChangeFloat(currentSignals["largest_holder_percentage"])
	currentTop10, top10OK := dossierChangeFloat(currentSignals["top_10_holder_percentage"])
	if len(arm) == 0 {
		return dossierChangeNotInvestigated("Holder Concentration did not produce a source row for change monitoring.")
	}
	if !top1OK || !top10OK {
		return dossierChangeUnavailable("Current role-adjusted holder concentration is unavailable.")
	}
	baseline := dossierMap(report["structural_memory"])
	if !dossierBool(baseline["has_holder_data"]) || !dossierChangeBaselineFresh(report, baseline, "holder_observed_at") {
		return map[string]any{
			"status": "monitoring_window_active", "evidence_status": "window_open",
			"current":     map[string]any{"top_1_pct": currentTop1, "top_10_pct": currentTop10},
			"changed":     nil,
			"method":      "compare_role_adjusted_holder_percentages_to_previous_verified_structural_memory",
			"limitations": []string{"A fresh previous compatible holder observation is required before a concentration change can be asserted."},
		}
	}
	previousTop1, previousTop1OK := dossierChangeFloat(baseline["largest_holder_percentage"])
	previousTop10, previousTop10OK := dossierChangeFloat(baseline["top_10_holder_percentage"])
	if !previousTop1OK || !previousTop10OK {
		return dossierChangeUnavailable("Previous structural holder percentages are incomplete.")
	}
	top1Delta := currentTop1 - previousTop1
	top10Delta := currentTop10 - previousTop10
	return map[string]any{
		"status": "verified", "evidence_status": "verified",
		"changed":                 top1Delta != 0 || top10Delta != 0,
		"concentration_increased": top1Delta > 0 || top10Delta > 0,
		"previous":                map[string]any{"top_1_pct": previousTop1, "top_10_pct": previousTop10},
		"current":                 map[string]any{"top_1_pct": currentTop1, "top_10_pct": currentTop10},
		"top_1_delta_points":      dossierChangeRound(top1Delta),
		"top_10_delta_points":     dossierChangeRound(top10Delta),
		"baseline_observed_at":    baseline["holder_observed_at"],
		"current_observed_at":     report["generated_at"],
		"method":                  "compare_role_adjusted_holder_percentages_to_previous_verified_structural_memory",
		"grade_effect":            "none_v1",
		"limitations":             []string{"This compares compatible role-adjusted snapshots; it does not infer common control or intent."},
	}
}

func deriveFailedAttemptWindow(report map[string]any) map[string]any {
	// Sniper Timing carries the bounded mint-signature window when complete.
	// Pump carries the same counters for Pump-applicable targets. Never infer an
	// exploit from generic failures; expose the count and boundary only.
	var arm map[string]any
	for _, moduleID := range []string{"sniper_timing_detector", "pump_sybil_radar"} {
		candidate := dossierChangeModule(report, moduleID)
		signals := dossierMap(candidate["signals"])
		if _, ok := dossierChangeFloat(signals["failed_signature_count"]); ok {
			arm = candidate
			break
		}
	}
	if len(arm) == 0 {
		return map[string]any{
			"status": "not_investigated", "evidence_status": "not_investigated",
			"limitations": []string{"No bounded failed-signature counter reached the immutable report."},
		}
	}
	signals := dossierMap(arm["signals"])
	failed, _ := dossierChangeFloat(signals["failed_signature_count"])
	total, _ := dossierChangeFloat(signals["recent_signature_count"])
	windowSeconds, _ := dossierChangeFloat(signals["signature_window_seconds"])
	return map[string]any{
		"status": "observed", "evidence_status": "observed",
		"failed_signature_count": int64(failed), "observed_signature_count": int64(total),
		"signature_window_seconds":   int64(windowSeconds),
		"repeated_failures_observed": failed >= 3,
		"source_module":              arm["module_id"],
		"method":                     "bounded_target_signature_failure_count",
		"grade_effect":               "none_v1",
		"limitations":                []string{"Failed transactions may be benign retries, slippage or compute errors; this row does not label them as an exploit without parsed instruction evidence."},
	}
}

func dossierChangeModule(report map[string]any, moduleID string) map[string]any {
	for _, item := range dossierSlice(dossierFirst(report["evidence_arms"], report["modules"])) {
		module := dossierMap(item)
		if strings.EqualFold(strings.TrimSpace(firstNonEmptyString(
			dossierString(module["module_id"]), dossierString(module["module"]),
		)), strings.TrimSpace(moduleID)) {
			return module
		}
	}
	return map[string]any{}
}

func dossierChangeNotInvestigated(reason string) map[string]any {
	return map[string]any{
		"status": "not_investigated", "evidence_status": "not_investigated",
		"limitations": []string{strings.TrimSpace(reason)},
	}
}

func dossierChangeUnavailable(reason string) map[string]any {
	return map[string]any{
		"status": "source_unavailable", "evidence_status": "source_unavailable",
		"limitations": []string{strings.TrimSpace(reason)},
	}
}

func dossierChangeBaselineFresh(report, baseline map[string]any, observedKey string) bool {
	current, err := time.Parse(time.RFC3339, strings.TrimSpace(dossierString(report["generated_at"])))
	if err != nil || current.IsZero() {
		return false
	}
	observed, err := time.Parse(time.RFC3339, strings.TrimSpace(dossierString(baseline[observedKey])))
	if err != nil || observed.IsZero() {
		return false
	}
	age := current.UTC().Sub(observed.UTC())
	return age >= -5*time.Minute && age <= dossierChangeBaselineMaxAge
}

func dossierChangeBool(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return false, false
	}
}

func dossierChangeFloat(value any) (float64, bool) {
	var out float64
	switch typed := value.(type) {
	case float64:
		out = typed
	case float32:
		out = float64(typed)
	case int:
		out = float64(typed)
	case int64:
		out = float64(typed)
	case uint64:
		out = float64(typed)
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return 0, false
		}
		out = parsed
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		if err != nil {
			return 0, false
		}
		out = parsed
	default:
		return 0, false
	}
	if math.IsNaN(out) || math.IsInf(out, 0) {
		return 0, false
	}
	return out, true
}

func dossierChangeRound(value float64) float64 {
	return math.Round(value*10000) / 10000
}

func init() {
	// Evidence references were historically initialized from a stale 20-row
	// list. Derive them from the canonical registry so every evidence-producing
	// row receives at least the target account reference.
	ids := make([]string, 0, len(signalRegistry))
	for _, def := range signalRegistry {
		ids = append(ids, def.ID)
	}
	unifiedVerdictCardRowIDs = ids
}
