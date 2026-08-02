package handlers

import "sort"

// attachFinalProductIntegrationDiagnostics keeps the existing canonical
// integration contract and promotes the final revenue-facing evidence surfaces
// into that same contract. A collector is not considered product-complete merely
// because its JSON happens to be present somewhere in the report.
func attachFinalProductIntegrationDiagnostics(report map[string]any) {
	attachCanonicalInvestigationDiagnostics(report)
	coverage := buildCanonicalIntegrationCoverage(report)

	// The Jupiter fixed-notional simulation and the Solana program authority/age
	// surface are first-class product outputs. They remain contextual evidence and
	// do not independently control the deterministic verdict.
	coverage.Capabilities["exit_liquidity"] = canonicalStatusFromRaw(
		"Jupiter fixed-notional exit liquidity simulation",
		report["exit_liquidity"],
		coverage.LiveScanRequested,
		false,
		"exit_liquidity",
	)
	coverage.Capabilities["program_security"] = canonicalStatusFromRaw(
		"Solana program authority and deployment-age evidence",
		report["program_security"],
		coverage.LiveScanRequested,
		false,
		"program_security",
	)

	// Discovery is Helius-first. Preserve the underlying report path while
	// removing the obsolete provider name from the capability contract.
	if legacy, ok := coverage.Capabilities["solscan_actor_discovery"]; ok {
		legacy.Capability = "Helius-first actor discovery and on-chain attribution"
		coverage.Capabilities["helius_actor_discovery"] = legacy
		delete(coverage.Capabilities, "solscan_actor_discovery")
	}

	markDisabledDefenseRuntimeOptional(report, &coverage)
	recountFinalProductCoverage(&coverage)
	report["capability_integration"] = coverage
}

func attachFinalWalletIntegrationDiagnostics(report map[string]any) {
	attachCanonicalWalletIntegrationCoverage(report)
	coverage, ok := report["capability_integration"].(canonicalIntegrationCoverage)
	if !ok {
		return
	}
	if legacy, exists := coverage.Capabilities["solscan_actor_discovery"]; exists {
		legacy.Capability = "Helius-first actor discovery and on-chain attribution"
		coverage.Capabilities["helius_actor_discovery"] = legacy
		delete(coverage.Capabilities, "solscan_actor_discovery")
	}
	recountFinalProductCoverage(&coverage)
	report["capability_integration"] = coverage
}

func markDisabledDefenseRuntimeOptional(report map[string]any, coverage *canonicalIntegrationCoverage) {
	if coverage == nil {
		return
	}
	if _, runtimeAttached := report["defense_agent_runtime"]; runtimeAttached {
		return
	}
	coverage.Capabilities["defense_agent_runtime"] = canonicalCapabilityStatus{
		Capability:            "Solana Defense shadow runtime",
		Status:                canonicalCapabilityNotRequested,
		WiredToCanonicalRadar: true,
		RequiredForFullScan:   false,
		EvidenceBacked:        false,
		Source:                "defense_agent_runtime",
		Limitations: []string{
			"Optional Defense OS runtime is disabled by configuration and does not block the core product scan.",
		},
	}
}

func recountFinalProductCoverage(coverage *canonicalIntegrationCoverage) {
	if coverage == nil {
		return
	}
	coverage.RequiredCapabilityCount = 0
	coverage.ActiveRequiredCount = 0
	coverage.PartialRequiredCount = 0
	coverage.UnavailableRequiredCount = 0
	coverage.NotRequestedRequiredCount = 0
	coverage.OrphanCapabilityCount = 0
	coverage.OrphanCapabilities = coverage.OrphanCapabilities[:0]

	keys := make([]string, 0, len(coverage.Capabilities))
	for key := range coverage.Capabilities {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		item := coverage.Capabilities[key]
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
