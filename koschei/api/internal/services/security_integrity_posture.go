package services

import "strings"

const SecurityIntegrityPostureVersion = "koschei-integrity-posture-v1"

type SecurityIntegrityPosture struct {
	Version        string         `json:"version"`
	Status         string         `json:"status"`
	VerdictReady   bool           `json:"verdict_ready"`
	FullVisibility bool           `json:"full_visibility"`
	Reasons        []string       `json:"reasons"`
	Components     map[string]any `json:"components"`
	Policy         map[string]any `json:"policy"`
}

func DeriveSecurityIntegrityPosture(
	continuity SecurityRadarContinuityReport,
	pump PumpPortalInboxHealth,
	trade PumpPortalTradeStreamHealth,
	providers ProviderWitnessMemoryReport,
) SecurityIntegrityPosture {
	out := SecurityIntegrityPosture{
		Version:        SecurityIntegrityPostureVersion,
		Status:         "healthy",
		VerdictReady:   true,
		FullVisibility: true,
		Reasons:        []string{},
		Components: map[string]any{
			"solana_stream_continuity": continuity.Status,
			"pumpportal_ingest":        pump.Status,
			"pumpportal_trade_stream":  trade.Status,
			"provider_witness_memory":  providers.Status,
		},
		Policy: map[string]any{
			"missing_visibility_never_becomes_safe":     true,
			"trade_visibility_is_not_verdict_authority": true,
			"provider_memory_never_auto_bans":           true,
			"partial_visibility_must_be_explicit":       true,
		},
	}

	continuityStatus := normalizePostureStatus(continuity.Status)
	pumpStatus := normalizePostureStatus(pump.Status)
	tradeStatus := normalizePostureStatus(trade.Status)
	providerStatus := normalizePostureStatus(providers.Status)

	// Durable discovery is a live evidence-ingress dependency. Exhaustion or an
	// unavailable database means new launch evidence can be missed or delayed.
	switch pumpStatus {
	case "degraded", "unavailable":
		out.Status = "degraded"
		out.VerdictReady = false
		out.FullVisibility = false
		out.Reasons = append(out.Reasons, "pumpportal_ingest_degraded")
	case "backlogged", "recovering":
		out.Status = worseIntegrityStatus(out.Status, "recovering")
		out.FullVisibility = false
		out.Reasons = append(out.Reasons, "pumpportal_ingest_recovering")
	}

	// Gap-healer continuity can legitimately be unavailable while broad WSS is
	// disabled by quota policy. That is partial visibility, not a fake outage and
	// never a claim that chain-wide observation is complete.
	switch continuityStatus {
	case "blocked", "degraded":
		out.Status = worseIntegrityStatus(out.Status, "degraded")
		out.FullVisibility = false
		out.Reasons = append(out.Reasons, "solana_stream_continuity_degraded")
	case "recovering":
		out.Status = worseIntegrityStatus(out.Status, "recovering")
		out.FullVisibility = false
		out.Reasons = append(out.Reasons, "solana_stream_recovery_in_progress")
	case "unavailable", "unknown", "":
		out.Status = worseIntegrityStatus(out.Status, "partial_visibility")
		out.FullVisibility = false
		out.Reasons = append(out.Reasons, "solana_stream_continuity_not_observed")
	}

	// PumpPortal trade data is an optional behavioral evidence arm. Missing or
	// rejected delivery narrows visibility but cannot invalidate deterministic
	// on-chain verdicts that do not depend on that arm.
	switch tradeStatus {
	case "subscription_rejected", "unavailable", "stale":
		out.Status = worseIntegrityStatus(out.Status, "partial_visibility")
		out.FullVisibility = false
		out.Reasons = append(out.Reasons, "pumpportal_trade_visibility_limited")
	case "not_configured", "no_trade_observed":
		out.Status = worseIntegrityStatus(out.Status, "partial_visibility")
		out.FullVisibility = false
		out.Reasons = append(out.Reasons, "pumpportal_trade_visibility_unverified")
	}

	switch providerStatus {
	case "attention_required":
		out.Status = worseIntegrityStatus(out.Status, "degraded")
		out.FullVisibility = false
		out.Reasons = append(out.Reasons, "provider_witness_divergence")
	case "degraded_availability":
		out.Status = worseIntegrityStatus(out.Status, "partial_visibility")
		out.FullVisibility = false
		out.Reasons = append(out.Reasons, "provider_witness_availability_degraded")
	}

	out.Reasons = uniqueIntegrityReasons(out.Reasons)
	return out
}

func uniqueIntegrityReasons(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizePostureStatus(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func worseIntegrityStatus(current, candidate string) string {
	rank := map[string]int{
		"healthy":            0,
		"partial_visibility": 1,
		"recovering":         2,
		"degraded":           3,
	}
	current = normalizePostureStatus(current)
	candidate = normalizePostureStatus(candidate)
	if rank[candidate] > rank[current] {
		return candidate
	}
	if current == "" {
		return candidate
	}
	return current
}
