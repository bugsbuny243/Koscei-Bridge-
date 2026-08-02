package handlers

// normalizeFinalProductCapabilityCoverage connects the final customer-visible
// market/program surfaces to the canonical integration contract. Optional
// Defense OS capability remains represented but never blocks the core product
// when deliberately disabled.
func normalizeFinalProductCapabilityCoverage(report map[string]any) {
	if report == nil {
		return
	}
	coverage, ok := report["capability_integration"].(canonicalIntegrationCoverage)
	if !ok {
		return
	}
	if coverage.Capabilities == nil {
		coverage.Capabilities = map[string]canonicalCapabilityStatus{}
	}
	live := coverage.LiveScanRequested
	coverage.Capabilities["exit_liquidity"] = canonicalStatusFromRaw(
		"Fixed-notional exit liquidity simulation", report["exit_liquidity"], live, false, "exit_liquidity",
	)
	coverage.Capabilities["program_security"] = canonicalStatusFromRaw(
		"Program upgrade authority and deployment age", report["program_security"], live, false, "program_security",
	)

	if stale, exists := coverage.Capabilities["solscan_actor_discovery"]; exists {
		delete(coverage.Capabilities, "solscan_actor_discovery")
		stale.Capability = "Helius-first actor discovery and attribution"
		coverage.Capabilities["helius_actor_discovery"] = stale
	}

	if _, attached := report["defense_agent_runtime"]; !attached {
		coverage.Capabilities["defense_agent_runtime"] = canonicalCapabilityStatus{
			Capability:            "Solana Defense shadow runtime",
			Status:                canonicalCapabilityNotRequested,
			WiredToCanonicalRadar: true,
			RequiredForFullScan:   false,
			EvidenceBacked:        false,
			Source:                "defense_agent_runtime",
			Limitations: []string{
				"Optional Defense OS capability is disabled by configuration and does not block the core product scan.",
			},
		}
	}

	recountFinalProductCapabilityCoverage(&coverage)
	report["capability_integration"] = coverage
}

func recountFinalProductCapabilityCoverage(coverage *canonicalIntegrationCoverage) {
	if coverage == nil {
		return
	}
	coverage.RequiredCapabilityCount = 0
	coverage.ActiveRequiredCount = 0
	coverage.PartialRequiredCount = 0
	coverage.UnavailableRequiredCount = 0
	coverage.NotRequestedRequiredCount = 0
	coverage.OrphanCapabilityCount = 0
	coverage.OrphanCapabilities = []string{}

	for key, item := range coverage.Capabilities {
		if !item.WiredToCanonicalRadar {
			coverage.OrphanCapabilityCount++
			coverage.OrphanCapabilities = append(coverage.OrphanCapabilities, key)
		}
		if !item.RequiredForFullScan {
			continue
		}
		coverage.RequiredCapabilityCount++
		switch item.Status {
		case canonicalCapabilityActive:
			coverage.ActiveRequiredCount++
		case canonicalCapabilityPartial:
			coverage.PartialRequiredCount++
		case canonicalCapabilityNotRequested:
			coverage.NotRequestedRequiredCount++
		default:
			coverage.UnavailableRequiredCount++
		}
	}

	if !coverage.LiveScanRequested {
		coverage.OverallStatus = "stored_or_preflight_projection"
		return
	}
	switch {
	case coverage.UnavailableRequiredCount > 0 || coverage.OrphanCapabilityCount > 0:
		coverage.OverallStatus = "blocked"
	case coverage.PartialRequiredCount > 0 || coverage.NotRequestedRequiredCount > 0:
		coverage.OverallStatus = "partial"
	default:
		coverage.OverallStatus = "complete"
	}
}
