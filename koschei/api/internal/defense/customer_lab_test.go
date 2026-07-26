package defense

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSummarizeCustomerLabDecisions(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		decision string
	}{
		{name: "critical blocks", findings: []Finding{{Severity: "critical"}}, decision: "block"},
		{name: "high blocks", findings: []Finding{{Severity: "high"}}, decision: "block"},
		{name: "medium warns", findings: []Finding{{Severity: "medium"}}, decision: "warn"},
		{name: "low reviews", findings: []Finding{{Severity: "low"}}, decision: "review"},
		{name: "empty is not a guarantee", findings: nil, decision: "no_static_trigger"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := summarizeCustomerLab(LabReport{DetectorVersion: DetectorVersion, Findings: tt.findings, ReportHash: "sha256:test"}, "KDA1-test")
			if summary.Decision != tt.decision {
				t.Fatalf("decision=%s want=%s", summary.Decision, tt.decision)
			}
			if summary.FindingCount != len(tt.findings) {
				t.Fatalf("finding_count=%d want=%d", summary.FindingCount, len(tt.findings))
			}
			if strings.TrimSpace(summary.RecommendedAction) == "" {
				t.Fatal("recommended action is empty")
			}
		})
	}
	if !strings.Contains(strings.ToLower(customerLabAction("no_static_trigger")), "garantisi") {
		t.Fatal("no-static-trigger action does not reject a safety guarantee")
	}
}

func TestCustomerProgramLabUsesExistingDeterministicDetectors(t *testing.T) {
	bundle, err := json.Marshal(map[string]string{
		"programs/audit/src/lib.rs": "pub fn transfer() { unsafe { invoke_unchecked(&ix, &accounts); } }",
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := Artifact{
		ArtifactRef: "KDA1-0123456789abcdef0123456789abcdef",
		ProgramID: "AuditProgram1111111111111111111111111111",
		Network: "solana-mainnet", ArtifactType: "source_bundle",
		ContentHash: hashValue(bundle), ContentEncoding: "json", Content: bundle,
		TrustLevel: "unverified", Verified: false,
	}
	report, err := AnalyzeArtifact(artifact)
	if err != nil {
		t.Fatalf("analyze artifact: %v", err)
	}
	foundHigh := false
	for _, finding := range report.Findings {
		if finding.RuleID == "KPS-S003" && finding.Severity == "high" {
			foundHigh = true
		}
		if finding.VerdictAuthority {
			t.Fatalf("static finding gained verdict authority: %#v", finding)
		}
	}
	if !foundHigh {
		t.Fatalf("KPS-S003 high finding missing: %#v", report.Findings)
	}
	summary := summarizeCustomerLab(report, artifact.ArtifactRef)
	if summary.Decision != "block" {
		t.Fatalf("decision=%s want=block", summary.Decision)
	}
	if report.ReportHash == "" || summary.ReportHash != report.ReportHash {
		t.Fatalf("report hash missing or changed: report=%s summary=%s", report.ReportHash, summary.ReportHash)
	}
}

func TestCustomerArtifactTypesStayNonExecutable(t *testing.T) {
	for _, allowed := range []string{"source_bundle", "source_manifest", "sbpf_manifest", "anchor_idl"} {
		if !customerArtifactTypes[allowed] {
			t.Fatalf("expected customer artifact type %s to be allowed", allowed)
		}
	}
	for _, forbidden := range []string{"synthetic_source_bundle", "sbpf_bytecode", "knowledge_document", "command", "executable"} {
		if customerArtifactTypes[forbidden] {
			t.Fatalf("unsafe customer artifact type %s is allowed", forbidden)
		}
	}
}
