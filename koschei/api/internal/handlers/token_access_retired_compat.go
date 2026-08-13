package handlers

import (
	"errors"
	"math/big"
)

// tokenTierThresholdEnv remains only so historical owner/readiness surfaces can
// render a non-authoritative tombstone while those surfaces are being removed.
// Token holdings no longer grant product access.
func tokenTierThresholdEnv(name, fallback string) string {
	return "retired"
}

// configuredTokenThresholds is deliberately fail-closed. A deployment that
// still enables the retired token gate must be reported as invalid rather than
// silently restoring balance-based authorization.
func configuredTokenThresholds(decimals int) (map[string]string, map[string]*big.Int, error) {
	return nil, nil, errors.New("KOSCH token-tier authorization retired; use SaaS entitlements")
}
