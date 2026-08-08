package http

import (
	"encoding/json"
	"net/http"

	"koschei/api/internal/runtimecfg"
)

type runtimeFeature string

const (
	featureSolana            runtimeFeature = "solana"
	featureRiskScanner       runtimeFeature = "risk_scanner"
	featurePublicBadge       runtimeFeature = "public_badge"
	featureLaunchPageBuilder runtimeFeature = "launch_page_builder"
)

func runtimeFeatureEnabled(feature runtimeFeature) bool {
	cfg := runtimecfg.Load()
	switch feature {
	case featureSolana:
		return cfg.SolanaEnabled
	case featureRiskScanner:
		return cfg.RiskScannerEnabled
	case featurePublicBadge:
		return cfg.PublicBadgeEnabled
	case featureLaunchPageBuilder:
		return cfg.LaunchPageBuilderEnabled
	default:
		return false
	}
}

func requireRuntimeFeature(feature runtimeFeature, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !runtimeFeatureEnabled(feature) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":      false,
				"code":    "feature_disabled",
				"feature": string(feature),
			})
			return
		}
		next(w, r)
	}
}
