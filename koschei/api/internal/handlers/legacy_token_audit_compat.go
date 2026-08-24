package handlers

import (
	"os"
	"strings"
)

// These helpers exist only for legacy owner/audit surfaces that may display
// historical KOSCH configuration. They MUST NOT be used for customer access,
// plan selection, quotas, API permissions, discounts, evidence or verdicts.
func configuredKoscheiTokenMint() string {
	return strings.TrimSpace(firstNonEmptyString(os.Getenv("KOSCHEI_TOKEN_MINT"), os.Getenv("KOSCH_TOKEN_MINT")))
}

// Commercial KOSCH gating is permanently retired. Returning false prevents old
// owner telemetry from being mistaken for a live authorization control.
func configuredKoscheiTokenGateEnabled() bool { return false }

// Retained solely to label historical owner telemetry. Thresholds are not an
// authorization source and are never consumed by the SaaS route gates.
func tokenTierThresholdEnv(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
