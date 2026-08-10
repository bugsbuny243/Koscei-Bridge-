package handlers

import "strings"

// KOSCH security capabilities are access/coordination permissions only.
//
// Actor Investigation Engine refs: sections 3-5 (evidence/verdict authority).
// Actor ruleset: v1.0. Unified Radar final authority remains deterministic.
//
// Token holdings MUST NOT grant evidence mutation, verdict override, compiler
// bypass, Sentinel promotion, privilege expansion, or integration approval.
const (
	koschCapabilityIdentityProof      = "identity.proof"
	koschCapabilityBasicSecurityScan  = "security.scan.basic"
	koschCapabilityAdvancedRadar      = "security.radar.advanced"
	koschCapabilityExposureReport     = "security.exposure.report"
	koschCapabilityActorGraph         = "intelligence.actor_graph"
	koschCapabilityEvidenceExport     = "intelligence.evidence_export"
	koschCapabilityWatchlist          = "security.watchlist"
	koschCapabilityWebhooks           = "developer.webhooks"
	koschCapabilityDeveloperAPI       = "developer.api"
	koschCapabilityAdvancedAgents     = "developer.deterministic_agents"
	koschCapabilityContributionSubmit = "security.contribution.submit"
)

// These names are deliberately reserved as non-grantable powers. Keeping the
// deny set explicit makes accidental future token-authority expansion testable.
var koschNeverGrantCapabilities = map[string]struct{}{
	"evidence.write":             {},
	"evidence.mutate":            {},
	"verdict.override":           {},
	"verdict.lower_risk":         {},
	"verdict.publish_bypass":     {},
	"capability.grant":           {},
	"capability.expand":          {},
	"compiler.bypass":            {},
	"compiler.policy_override":   {},
	"sentinel.promote":           {},
	"sentinel.deploy":            {},
	"sentinel.verdict_authority": {},
	"integration.approve":        {},
}

var koschTierCapabilities = map[string][]string{
	"basic": {
		koschCapabilityIdentityProof,
		koschCapabilityBasicSecurityScan,
		koschCapabilityContributionSubmit,
	},
	"pro": {
		koschCapabilityIdentityProof,
		koschCapabilityBasicSecurityScan,
		koschCapabilityAdvancedRadar,
		koschCapabilityExposureReport,
		koschCapabilityActorGraph,
		koschCapabilityWatchlist,
		koschCapabilityContributionSubmit,
	},
	"enterprise": {
		koschCapabilityIdentityProof,
		koschCapabilityBasicSecurityScan,
		koschCapabilityAdvancedRadar,
		koschCapabilityExposureReport,
		koschCapabilityActorGraph,
		koschCapabilityEvidenceExport,
		koschCapabilityWatchlist,
		koschCapabilityWebhooks,
		koschCapabilityDeveloperAPI,
		koschCapabilityAdvancedAgents,
		koschCapabilityContributionSubmit,
	},
}

func koschSecurityCapabilitiesForTier(tier string) []string {
	tier = strings.ToLower(strings.TrimSpace(tier))
	configured := koschTierCapabilities[tier]
	out := make([]string, 0, len(configured))
	for _, capability := range configured {
		capability = strings.TrimSpace(capability)
		if capability == "" || koschCapabilityIsNeverGrantable(capability) {
			continue
		}
		out = append(out, capability)
	}
	return out
}

func koschSecurityCapabilityAllowed(tier, capability string) bool {
	capability = strings.TrimSpace(capability)
	if capability == "" || koschCapabilityIsNeverGrantable(capability) {
		return false
	}
	for _, granted := range koschSecurityCapabilitiesForTier(tier) {
		if granted == capability {
			return true
		}
	}
	return false
}

func koschCapabilityIsNeverGrantable(capability string) bool {
	_, blocked := koschNeverGrantCapabilities[strings.TrimSpace(capability)]
	return blocked
}

// koschTierAuthorizes preserves the existing basic/pro/enterprise ordering but
// routes the decision through named, non-security-authority capabilities.
func koschTierAuthorizes(current, required string) bool {
	required = strings.ToLower(strings.TrimSpace(required))
	if tokenTierRank(required) == 0 {
		return false
	}
	switch required {
	case "basic":
		return koschSecurityCapabilityAllowed(current, koschCapabilityBasicSecurityScan)
	case "pro":
		return koschSecurityCapabilityAllowed(current, koschCapabilityAdvancedRadar)
	case "enterprise":
		return koschSecurityCapabilityAllowed(current, koschCapabilityDeveloperAPI)
	default:
		return false
	}
}
