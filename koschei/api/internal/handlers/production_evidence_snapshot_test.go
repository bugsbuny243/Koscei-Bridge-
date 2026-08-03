package handlers

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"koschei/api/internal/services"
)

func TestAttachCustomerAnalysisSummarySynchronizesCanonicalFinalVerdict(t *testing.T) {
	authoritative := services.UnifiedRadarVerdict{
		Grade:          "F",
		Verdict:        "hard_trigger",
		Signed:         true,
		Signature:      "koschei-unified:test-f",
		RulesetVersion: "rules-v1",
		ActorRuleset:   "actor-v1",
	}
	assembly := unifiedInvestigationAssembly{
		Report: map[string]any{
			"final_verdict": services.UnifiedRadarVerdict{
				Grade: "B", Verdict: "compounding_rule", Signed: true,
				Signature: "stale-b", RulesetVersion: "rules-v1",
			},
		},
		UnifiedVerdict: authoritative,
	}

	summary := attachCustomerAnalysisSummary(&assembly)
	reportFinal, ok := assembly.Report["final_verdict"].(services.UnifiedRadarVerdict)
	if !ok {
		t.Fatalf("canonical final verdict type=%T", assembly.Report["final_verdict"])
	}
	if reportFinal.Grade != authoritative.Grade || reportFinal.Signature != authoritative.Signature || reportFinal.Verdict != authoritative.Verdict {
		t.Fatalf("canonical report retained stale verdict: %#v", reportFinal)
	}
	decision, ok := summary["decision"].(map[string]any)
	if !ok {
		t.Fatalf("analysis decision missing: %#v", summary)
	}
	if decision["grade"] != authoritative.Grade || decision["signature"] != authoritative.Signature {
		t.Fatalf("summary/report verdict drift: summary=%#v report=%#v", decision, reportFinal)
	}
}

func TestProductionEvidenceSnapshot(t *testing.T) {
	path := filepath.Join("..", "..", "evidence", "production-full-scan", "2026-08-03-kosch.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read production evidence snapshot: %v", err)
	}

	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{
		`"authorization"`, `"cookie"`, `"set-cookie"`, `"password"`,
		`"database_url"`, `"alchemy_api_key"`, `"private_key"`,
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("production snapshot contains forbidden secret-like field %s", forbidden)
		}
	}

	var snapshot struct {
		SchemaVersion string `json:"schema_version"`
		Target        string `json:"target"`
		Network       string `json:"network"`
		Endpoint      string `json:"endpoint"`
		Decision      struct {
			Grade           string `json:"grade"`
			Verdict         string `json:"verdict"`
			Signed          bool   `json:"signed"`
			Signature       string `json:"signature"`
			Confidence      string `json:"confidence"`
			Readiness       string `json:"readiness"`
			HasLiveEvidence bool   `json:"has_live_evidence"`
		} `json:"authoritative_decision"`
		Coverage struct {
			ArchitectureArmCount int  `json:"architecture_arm_count"`
			Observed             int  `json:"observed"`
			Pending              int  `json:"pending"`
			NotApplicable        int  `json:"not_applicable"`
			CoveragePercent      int  `json:"coverage_percent"`
			CoverageIsRiskScore  bool `json:"coverage_is_risk_score"`
		} `json:"evidence_coverage"`
		Modules []struct {
			ModuleID string `json:"module_id"`
			State    string `json:"state"`
		} `json:"evidence_modules"`
		Findings []struct {
			RuleID         string         `json:"rule_id"`
			EvidenceStatus string         `json:"evidence_status"`
			GradeEffect    string         `json:"grade_effect"`
			Signatures     []string       `json:"signatures"`
			Facts          map[string]any `json:"facts"`
		} `json:"grade_changing_findings"`
		Unresolved []map[string]any `json:"unresolved_questions"`
		Live       struct {
			Status               string `json:"status"`
			WalletsRequested     int    `json:"wallets_requested"`
			WalletsCompleted     int    `json:"wallets_completed"`
			SignaturesSeen       int    `json:"signatures_seen"`
			TransactionsParsed   int    `json:"transactions_parsed"`
			RelevantTransactions int    `json:"relevant_transactions"`
			RPCFailures          int    `json:"rpc_failures"`
		} `json:"live_evidence"`
		Actor struct {
			RunStatus string `json:"run_status"`
		} `json:"actor_investigation"`
		Provenance struct {
			ProductionCommit             string `json:"production_commit"`
			ArtifactDigest               string `json:"artifact_digest"`
			SourceFullScanResponseSHA256 string `json:"source_full_scan_response_sha256"`
			SourceFullScanResultSHA256   string `json:"source_full_scan_result_sha256"`
			AuthoritativeDecisionPath    string `json:"authoritative_decision_path"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("decode production evidence snapshot: %v", err)
	}

	if snapshot.SchemaVersion != "koschei-production-evidence-snapshot-v1" {
		t.Fatalf("schema_version=%q", snapshot.SchemaVersion)
	}
	if snapshot.Target != "HHPpU9u56Bwxov12nf7DXUCuv6h1q5j1xgGS3yukpump" || snapshot.Network != "solana-mainnet" || snapshot.Endpoint != "/api/token/scan" {
		t.Fatalf("unexpected target contract: target=%q network=%q endpoint=%q", snapshot.Target, snapshot.Network, snapshot.Endpoint)
	}
	if snapshot.Decision.Grade != "F" || snapshot.Decision.Verdict != "hard_trigger" || !snapshot.Decision.Signed || snapshot.Decision.Signature == "" || !snapshot.Decision.HasLiveEvidence {
		t.Fatalf("authoritative decision is incomplete: %#v", snapshot.Decision)
	}
	if snapshot.Decision.Confidence != "medium" || snapshot.Decision.Readiness != "actionable_with_gaps" {
		t.Fatalf("unexpected confidence/readiness: %#v", snapshot.Decision)
	}
	if snapshot.Coverage.ArchitectureArmCount != 14 || len(snapshot.Modules) != 14 {
		t.Fatalf("14-arm contract drift: coverage=%d modules=%d", snapshot.Coverage.ArchitectureArmCount, len(snapshot.Modules))
	}
	if snapshot.Coverage.Observed != 9 || snapshot.Coverage.Pending != 3 || snapshot.Coverage.NotApplicable != 2 || snapshot.Coverage.CoveragePercent != 75 || snapshot.Coverage.CoverageIsRiskScore {
		t.Fatalf("unexpected evidence coverage: %#v", snapshot.Coverage)
	}

	pending := []string{}
	for _, module := range snapshot.Modules {
		if module.State == "pending" {
			pending = append(pending, module.ModuleID)
		}
	}
	sort.Strings(pending)
	expectedPending := []string{"claim_surface_risk", "holder_concentration", "walletless_claim_shield"}
	if strings.Join(pending, ",") != strings.Join(expectedPending, ",") {
		t.Fatalf("pending arms=%v", pending)
	}

	if len(snapshot.Findings) != 5 {
		t.Fatalf("grade-changing findings=%d", len(snapshot.Findings))
	}
	foundFCap := false
	for _, finding := range snapshot.Findings {
		if finding.EvidenceStatus != "verified" {
			t.Fatalf("grade-changing finding is not verified: %#v", finding)
		}
		if finding.RuleID != "URD-C005" {
			if finding.RuleID != "ARD-C004" || len(finding.Signatures) < 2 {
				t.Fatalf("unexpected transfer finding: %#v", finding)
			}
			continue
		}
		metrics, _ := finding.Facts["metrics"].(map[string]any)
		share, _ := metrics["owner_resolved_top_share_pct"].(float64)
		if finding.GradeEffect == "hard_cap_F" && math.Abs(share-99.2987) < 0.0001 {
			foundFCap = true
		}
	}
	if !foundFCap {
		t.Fatal("verified URD-C005 F-cap evidence missing")
	}
	if len(snapshot.Unresolved) != 6 {
		t.Fatalf("unresolved_questions=%d", len(snapshot.Unresolved))
	}
	if snapshot.Live.Status != "complete" || snapshot.Live.WalletsRequested != 4 || snapshot.Live.WalletsCompleted != 4 || snapshot.Live.SignaturesSeen != 97 || snapshot.Live.TransactionsParsed != 43 || snapshot.Live.RelevantTransactions != 16 || snapshot.Live.RPCFailures != 0 {
		t.Fatalf("unexpected live evidence: %#v", snapshot.Live)
	}
	if snapshot.Actor.RunStatus != "partial" {
		t.Fatalf("actor run status=%q", snapshot.Actor.RunStatus)
	}
	if snapshot.Provenance.ProductionCommit != "bac03e410ee366617cfcc5a7c421f733f5450a9d" || snapshot.Provenance.AuthoritativeDecisionPath != "analysis_summary.decision" {
		t.Fatalf("unexpected provenance: %#v", snapshot.Provenance)
	}
	for name, value := range map[string]string{
		"artifact_digest":                 snapshot.Provenance.ArtifactDigest,
		"source_full_scan_response_sha256": snapshot.Provenance.SourceFullScanResponseSHA256,
		"source_full_scan_result_sha256":   snapshot.Provenance.SourceFullScanResultSHA256,
	} {
		if !strings.HasPrefix(value, "sha256:") && len(value) != 64 {
			t.Fatalf("%s is not a sha256 value: %q", name, value)
		}
	}

	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("decode generic snapshot: %v", err)
	}
	if _, exists := generic["final_verdict"]; exists {
		t.Fatal("permanent snapshot must expose only authoritative_decision, not a stale legacy final_verdict projection")
	}
}
