package handlers

import (
	"sort"
	"strings"
)

type investigationTransparencyItem struct {
	Capability string `json:"capability"`
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	Source     string `json:"source,omitempty"`
	Remediable bool   `json:"remediable"`
}

type investigationTransparencyReport struct {
	SchemaVersion  string                          `json:"schema_version"`
	EvidenceLimits []investigationTransparencyItem `json:"evidence_limits"`
	CollectionGaps []investigationTransparencyItem `json:"collection_gaps"`
	Policy         map[string]any                  `json:"policy"`
}

func buildInvestigationTransparency(coverage canonicalIntegrationCoverage) investigationTransparencyReport {
	out := investigationTransparencyReport{
		SchemaVersion:  "koschei-investigation-transparency-v1",
		EvidenceLimits: []investigationTransparencyItem{},
		CollectionGaps: []investigationTransparencyItem{},
		Policy: map[string]any{
			"no_evidence_no_claim":                    true,
			"unknown_is_not_safe":                     true,
			"collection_gap_is_not_evidence_absence":  true,
			"bounded_observation_is_not_full_history": true,
		},
	}

	keys := make([]string, 0, len(coverage.Capabilities))
	for key := range coverage.Capabilities {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		capability := coverage.Capabilities[key]
		if capability.Status == canonicalCapabilityActive {
			continue
		}
		limitations := capability.Limitations
		if len(limitations) == 0 {
			limitations = []string{"Capability did not produce complete evidence in this investigation."}
		}
		for _, limitation := range limitations {
			reason := strings.TrimSpace(limitation)
			if reason == "" {
				continue
			}
			item := investigationTransparencyItem{
				Capability: capability.Capability,
				Status:     capability.Status,
				Reason:     reason,
				Source:     capability.Source,
			}
			if isOperationalCollectionGap(capability.Status, reason) {
				item.Remediable = true
				out.CollectionGaps = append(out.CollectionGaps, item)
			} else {
				out.EvidenceLimits = append(out.EvidenceLimits, item)
			}
		}
	}
	return out
}

func isOperationalCollectionGap(status, reason string) bool {
	value := strings.ToLower(strings.TrimSpace(status + " " + reason))
	operationalMarkers := []string{
		"api key", "credential", "not configured", "configuration", "database",
		"rpc budget", "budget exhausted", "rate limit", "timeout", "timed out",
		"provider unavailable", "service unavailable", "failed", "missing",
		"not requested", "could not be decoded", "absent or empty", "orphan",
	}
	for _, marker := range operationalMarkers {
		if strings.Contains(value, marker) {
			return true
		}
	}
	if status == canonicalCapabilityUnavailable || status == canonicalCapabilityNotRequested {
		return true
	}
	return false
}
