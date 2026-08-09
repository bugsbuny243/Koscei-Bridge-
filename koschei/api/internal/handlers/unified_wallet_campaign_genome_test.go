package handlers

import "testing"

func TestCampaignGenomeIsWiredAsOptionalWalletCapability(t *testing.T) {
	report := map[string]any{
		"actor_investigation": map[string]any{
			"campaign_genome": map[string]any{
				"version":              "koschei-technical-campaign-genome-v1",
				"status":               "verified_supported",
				"complete":             true,
				"genome_id":            "KCG1-0123456789ABCDEF",
				"evidence_hash_sha256": "sha256:fixture",
				"descriptor_count":     4,
				"limitations":          []string{},
			},
		},
		"full_scan_live_evidence": map[string]any{"status": "complete"},
	}
	attachCanonicalWalletIntegrationCoverage(report)
	coverage, ok := report["capability_integration"].(canonicalIntegrationCoverage)
	if !ok {
		t.Fatalf("coverage=%#v", report["capability_integration"])
	}
	capability, ok := coverage.Capabilities["actor_campaign_genome"]
	if !ok {
		t.Fatalf("capabilities=%#v", coverage.Capabilities)
	}
	if !capability.WiredToCanonicalRadar || capability.RequiredForFullScan || capability.Status != canonicalCapabilityActive || !capability.EvidenceBacked {
		t.Fatalf("capability=%#v", capability)
	}
}

func TestObservedOnlyCampaignGenomeDoesNotChangeRequiredWalletCoverage(t *testing.T) {
	baseline := map[string]any{
		"actor_investigation":     map[string]any{},
		"full_scan_live_evidence": map[string]any{"status": "complete"},
	}
	attachCanonicalWalletIntegrationCoverage(baseline)
	baselineCoverage := baseline["capability_integration"].(canonicalIntegrationCoverage)

	report := map[string]any{
		"actor_investigation": map[string]any{
			"campaign_genome": map[string]any{
				"version":              "koschei-technical-campaign-genome-v1",
				"status":               "observed_only",
				"complete":             false,
				"evidence_hash_sha256": "sha256:fixture",
				"descriptor_count":     3,
				"limitations":          []string{"No VERIFIED signature-backed anchor."},
			},
		},
		"full_scan_live_evidence": map[string]any{"status": "complete"},
	}
	attachCanonicalWalletIntegrationCoverage(report)
	coverage := report["capability_integration"].(canonicalIntegrationCoverage)
	capability := coverage.Capabilities["actor_campaign_genome"]
	if capability.RequiredForFullScan {
		t.Fatalf("campaign genome became mandatory: %#v", capability)
	}
	if coverage.RequiredCapabilityCount != baselineCoverage.RequiredCapabilityCount {
		t.Fatalf("optional campaign genome changed required capability count: baseline=%d candidate=%d", baselineCoverage.RequiredCapabilityCount, coverage.RequiredCapabilityCount)
	}
}
