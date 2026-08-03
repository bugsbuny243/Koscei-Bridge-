package handlers

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"koschei/api/internal/services"
)

type productionEvidenceFinding struct {
	RuleID         string         `json:"rule_id"`
	EvidenceStatus string         `json:"evidence_status"`
	GradeEffect    string         `json:"grade_effect"`
	EvidenceKeys   []string       `json:"evidence_keys"`
	Signatures     []string       `json:"signatures"`
	Facts          map[string]any `json:"facts"`
	EvidenceFile   string         `json:"evidence_file"`
}

type productionEvidenceRow struct {
	EvidenceKey       string         `json:"evidence_key"`
	Signature         string         `json:"signature"`
	Slot              int64          `json:"slot"`
	Timestamp         string         `json:"timestamp"`
	SourceWallet      string         `json:"source_wallet"`
	DestinationWallet string         `json:"destination_wallet"`
	Amount            map[string]any `json:"amount"`
	Program           string         `json:"program"`
	Verification      string         `json:"verification_status"`
	Relation          string         `json:"relation"`
	Source            string         `json:"source"`
	Network           string         `json:"network"`
}

type productionEvidenceSnapshot struct {
	SchemaVersion string `json:"schema_version"`
	Target        string `json:"target"`
	Network       string `json:"network"`
	Endpoint      string `json:"endpoint"`
	SourceDecision struct {
		Grade           string `json:"grade"`
		Verdict         string `json:"verdict"`
		Signed          bool   `json:"signed"`
		Signature       string `json:"signature"`
		Confidence      string `json:"confidence"`
		Readiness       string `json:"readiness"`
		RulesetVersion  string `json:"ruleset_version"`
		ActorRuleset    string `json:"actor_ruleset"`
		HasLiveEvidence bool   `json:"has_live_evidence"`
	} `json:"source_decision"`
	Interpretation struct {
		Grade                      string   `json:"grade"`
		Verdict                    string   `json:"verdict"`
		GradeDeterminingRuleCount  int      `json:"grade_determining_rule_count"`
		GradeDeterminingRuleIDs    []string `json:"grade_determining_rule_ids"`
		SupportingEvidenceGroups  int      `json:"supporting_evidence_group_count"`
		DistinctCompoundingCount  int      `json:"distinct_compounding_rule_count"`
		DistinctCompoundingRuleIDs []string `json:"distinct_compounding_rule_ids"`
		CorrectedRuleset           string   `json:"corrected_ruleset"`
	} `json:"authoritative_interpretation"`
	Coverage struct {
		ArchitectureArmCount int               `json:"architecture_arm_count"`
		Observed             int               `json:"observed"`
		Pending              int               `json:"pending"`
		NotApplicable        int               `json:"not_applicable"`
		CoveragePercent      int               `json:"coverage_percent"`
		CoverageIsRiskScore  bool              `json:"coverage_is_risk_score"`
		ModuleStates         map[string]string `json:"module_states"`
	} `json:"evidence_coverage"`
	GradeDetermining []productionEvidenceFinding `json:"grade_determining_findings"`
	Supporting       []productionEvidenceFinding `json:"supporting_rule_groups"`
	Unresolved       struct {
		Count int `json:"count"`
	} `json:"unresolved_questions"`
	Live struct {
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
		InterpretationPath           string `json:"authoritative_interpretation_path"`
	} `json:"provenance"`
}

func TestProductionEvidenceSnapshot(t *testing.T) {
	root := filepath.Join("..", "..", "evidence", "production-full-scan")
	raw := readEvidenceFile(t, filepath.Join(root, "2026-08-03-kosch.json"))
	assertNoSecretLikeFields(t, raw)

	var snapshot productionEvidenceSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("decode production evidence snapshot: %v", err)
	}
	if snapshot.SchemaVersion != "koschei-production-evidence-snapshot-v2" {
		t.Fatalf("schema_version=%q", snapshot.SchemaVersion)
	}
	if snapshot.Target != "HHPpU9u56Bwxov12nf7DXUCuv6h1q5j1xgGS3yukpump" || snapshot.Network != "solana-mainnet" || snapshot.Endpoint != "/api/token/scan" {
		t.Fatalf("unexpected target contract: %#v", snapshot)
	}
	if snapshot.SourceDecision.Grade != "F" || snapshot.SourceDecision.Verdict != "hard_trigger" || !snapshot.SourceDecision.Signed || snapshot.SourceDecision.Signature == "" || !snapshot.SourceDecision.HasLiveEvidence {
		t.Fatalf("source decision incomplete: %#v", snapshot.SourceDecision)
	}
	if snapshot.SourceDecision.RulesetVersion != "koschei-unified-radar-rules-v1.1.0" || snapshot.SourceDecision.ActorRuleset != services.ActorDefenseRulesetVersion {
		t.Fatalf("source provenance rulesets drifted: %#v", snapshot.SourceDecision)
	}
	if snapshot.Interpretation.Grade != "F" || snapshot.Interpretation.GradeDeterminingRuleCount != 1 || snapshot.Interpretation.SupportingEvidenceGroups != 4 || snapshot.Interpretation.DistinctCompoundingCount != 1 {
		t.Fatalf("corrected grading semantics missing: %#v", snapshot.Interpretation)
	}
	if strings.Join(snapshot.Interpretation.GradeDeterminingRuleIDs, ",") != "URD-C005" || strings.Join(snapshot.Interpretation.DistinctCompoundingRuleIDs, ",") != "ARD-C004" || snapshot.Interpretation.CorrectedRuleset != services.UnifiedRadarRulesetVersionV110 {
		t.Fatalf("corrected rule IDs/ruleset drifted: %#v", snapshot.Interpretation)
	}
	if snapshot.Coverage.ArchitectureArmCount != 14 || len(snapshot.Coverage.ModuleStates) != 14 || snapshot.Coverage.Observed != 9 || snapshot.Coverage.Pending != 3 || snapshot.Coverage.NotApplicable != 2 || snapshot.Coverage.CoveragePercent != 75 || snapshot.Coverage.CoverageIsRiskScore {
		t.Fatalf("unexpected evidence coverage: %#v", snapshot.Coverage)
	}
	pending := []string{}
	for moduleID, state := range snapshot.Coverage.ModuleStates {
		if state == "pending" {
			pending = append(pending, moduleID)
		}
	}
	sort.Strings(pending)
	if strings.Join(pending, ",") != "claim_surface_risk,holder_concentration,walletless_claim_shield" {
		t.Fatalf("pending arms=%v", pending)
	}
	if len(snapshot.GradeDetermining) != 1 || snapshot.GradeDetermining[0].RuleID != services.UnifiedRuleOwnerConcentration || snapshot.GradeDetermining[0].GradeEffect != "hard_cap_F" || snapshot.GradeDetermining[0].EvidenceStatus != "verified" {
		t.Fatalf("grade-determining finding incorrect: %#v", snapshot.GradeDetermining)
	}
	metrics, _ := snapshot.GradeDetermining[0].Facts["metrics"].(map[string]any)
	share, _ := metrics["owner_resolved_top_share_pct"].(float64)
	if math.Abs(share-99.2987) >= 0.0001 {
		t.Fatalf("owner-resolved share=%f", share)
	}
	if len(snapshot.Supporting) != 4 {
		t.Fatalf("supporting evidence groups=%d", len(snapshot.Supporting))
	}

	allRows := map[string]productionEvidenceRow{}
	for _, group := range snapshot.Supporting {
		if group.RuleID != services.ActorRuleCompoundRepeatedTransfer || group.GradeEffect != "supporting_context" || group.EvidenceFile == "" {
			t.Fatalf("supporting group semantics incorrect: %#v", group)
		}
		groupRaw := readEvidenceFile(t, filepath.Join(root, filepath.FromSlash(group.EvidenceFile)))
		assertNoSecretLikeFields(t, groupRaw)
		var evidence struct {
			RuleID       string                  `json:"rule_id"`
			EvidenceRows []productionEvidenceRow `json:"evidence_rows"`
		}
		if err := json.Unmarshal(groupRaw, &evidence); err != nil {
			t.Fatalf("decode %s: %v", group.EvidenceFile, err)
		}
		if evidence.RuleID != services.ActorRuleCompoundRepeatedTransfer {
			t.Fatalf("evidence file rule=%q", evidence.RuleID)
		}
		for _, row := range evidence.EvidenceRows {
			assertCompleteEvidenceRow(t, row)
			if _, duplicate := allRows[row.EvidenceKey]; duplicate {
				t.Fatalf("duplicate evidence key %s", row.EvidenceKey)
			}
			allRows[row.EvidenceKey] = row
		}
		for _, key := range group.EvidenceKeys {
			if _, exists := allRows[key]; !exists {
				t.Fatalf("group %s is missing complete evidence row %s", group.EvidenceFile, key)
			}
		}
	}
	if len(allRows) != 12 {
		t.Fatalf("complete permanent evidence rows=%d", len(allRows))
	}
	if snapshot.Unresolved.Count != 6 || snapshot.Live.Status != "complete" || snapshot.Live.WalletsRequested != 4 || snapshot.Live.WalletsCompleted != 4 || snapshot.Live.SignaturesSeen != 97 || snapshot.Live.TransactionsParsed != 43 || snapshot.Live.RelevantTransactions != 16 || snapshot.Live.RPCFailures != 0 || snapshot.Actor.RunStatus != "partial" {
		t.Fatalf("production evidence counts drifted: unresolved=%d live=%#v actor=%#v", snapshot.Unresolved.Count, snapshot.Live, snapshot.Actor)
	}
	if snapshot.Provenance.ProductionCommit != "bac03e410ee366617cfcc5a7c421f733f5450a9d" || snapshot.Provenance.InterpretationPath != "authoritative_interpretation" {
		t.Fatalf("unexpected provenance: %#v", snapshot.Provenance)
	}
	for name, value := range map[string]string{
		"artifact_digest":                   snapshot.Provenance.ArtifactDigest,
		"source_full_scan_response_sha256": snapshot.Provenance.SourceFullScanResponseSHA256,
		"source_full_scan_result_sha256":   snapshot.Provenance.SourceFullScanResultSHA256,
	} {
		if !strings.HasPrefix(value, "sha256:") && len(value) != 64 {
			t.Fatalf("%s is not a sha256 value: %q", name, value)
		}
	}
}

func TestCanonicalVerdictSynchronizationRunsBeforeSnapshotDiagnostics(t *testing.T) {
	actor := services.ActorDefenseRuleVerdict{
		RulesetVersion: services.ActorDefenseRulesetVersion,
		TriggeredRules: repeatedTransferGroups(4),
		WatchFlags:     []services.ActorDefenseRuleHit{},
	}
	behavior := ownerConcentrationBehavior()
	report := map[string]any{
		"target": "MintSync111",
		"network": "solana-mainnet",
		"final_verdict": services.UnifiedRadarVerdict{
			Grade: "B", Verdict: "compounding_rule", Signed: true,
			Signature: "stale-b", RulesetVersion: "koschei-unified-radar-rules-v1.1.0",
		},
		"actor_investigation": map[string]any{"rule_verdict": actor},
		"behavior_signals":    behavior,
	}
	attachFinalProductIntegrationDiagnostics(report)
	var final services.UnifiedRadarVerdict
	if !decodeCanonicalVerdictValue(report["final_verdict"], &final) {
		t.Fatal("synchronized final verdict missing")
	}
	if final.Grade != "F" || final.Verdict != "hard_trigger" || !final.Signed || final.RulesetVersion != services.UnifiedRadarRulesetVersionV110 || final.Signature == "stale-b" {
		t.Fatalf("stale verdict survived pre-snapshot diagnostics: %#v", final)
	}
	joined := strings.Join(final.DecisionPath, "\n")
	if strings.Contains(joined, "5 distinct") || !strings.Contains(joined, "only one distinct compounding rule ID") {
		t.Fatalf("incorrect synchronized decision path: %s", joined)
	}
}

func TestCustomerAnalysisSummaryV3SeparatesDeterminingAndSupportingFindings(t *testing.T) {
	actor := services.ActorDefenseRuleVerdict{RulesetVersion: services.ActorDefenseRulesetVersion, TriggeredRules: repeatedTransferGroups(4), WatchFlags: []services.ActorDefenseRuleHit{}}
	behavior := ownerConcentrationBehavior()
	final := services.EvaluateUnifiedRadarVerdictV110("MintSummary111", actor, behavior)
	assembly := unifiedInvestigationAssembly{UnifiedVerdict: final, Behavior: behavior}
	summary := buildCustomerAnalysisSummaryV3(assembly, true)
	if summary["schema_version"] != customerAnalysisSummarySchemaVersionV3 {
		t.Fatalf("schema=%v", summary["schema_version"])
	}
	determining, _ := summary["grade_changing_findings"].([]map[string]any)
	supporting, _ := summary["supporting_findings"].([]map[string]any)
	groups, _ := summary["triggered_evidence_groups"].([]map[string]any)
	decision, _ := summary["decision"].(map[string]any)
	if len(determining) != 1 || determining[0]["rule_id"] != services.UnifiedRuleOwnerConcentration || len(supporting) != 4 || len(groups) != 5 {
		t.Fatalf("v3 classification incorrect: determining=%#v supporting=%#v groups=%#v", determining, supporting, groups)
	}
	if decision["grade_determining_rule_count"] != 1 || decision["distinct_compounding_rule_count"] != 1 || decision["triggered_evidence_group_count"] != 5 {
		t.Fatalf("v3 decision counts incorrect: %#v", decision)
	}
}

func repeatedTransferGroups(count int) []services.ActorDefenseRuleHit {
	out := make([]services.ActorDefenseRuleHit, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, services.ActorDefenseRuleHit{
			RuleID: services.ActorRuleCompoundRepeatedTransfer, Title: "Repeated direct transfer relation",
			Tier: "compounding", EvidenceStatus: "verified", GradeEffect: "compounding_input",
			Count: i + 2, Summary: "separate evidence group from the same deterministic rule",
			EvidenceKeys: []string{"evidence-key"}, Signatures: []string{"signature"},
		})
	}
	return out
}

func ownerConcentrationBehavior() services.UnifiedRadarBehaviorReport {
	return services.UnifiedRadarBehaviorReport{
		RulesetVersion: services.UnifiedRadarRulesetVersionV110,
		Signals: []services.UnifiedRadarSignal{{
			RuleID: services.UnifiedRuleOwnerConcentration, Title: "Owner-resolved dominant concentration",
			EvidenceStatus: "verified", Triggered: true, GradeEffect: "hard_cap_F",
			Scope: "owner_resolved_infrastructure_excluded_circulating_supply",
			Summary: "Owner-resolved top ownership met the F-cap threshold.",
			Metrics: map[string]any{"owner_resolved_top_share_pct": 99.2987}, Thresholds: map[string]any{"f_cap_pct": 70.0},
			EvidenceKeys: []string{"owner:dominant"}, Signatures: []string{}, Limitations: []string{}, ObservedAt: time.Now().UTC(),
		}},
		GeneratedAt: time.Now().UTC(),
	}
}

func readEvidenceFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

func assertNoSecretLikeFields(t *testing.T, raw []byte) {
	t.Helper()
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{`"authorization"`, `"cookie"`, `"set-cookie"`, `"password"`, `"database_url"`, `"alchemy_api_key"`, `"private_key"`} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("evidence snapshot contains forbidden secret-like field %s", forbidden)
		}
	}
}

func assertCompleteEvidenceRow(t *testing.T, row productionEvidenceRow) {
	t.Helper()
	if row.EvidenceKey == "" || row.Signature == "" || row.Slot <= 0 || row.Timestamp == "" || row.SourceWallet == "" || row.DestinationWallet == "" || len(row.Amount) == 0 || row.Program == "" || row.Verification != "verified" || row.Relation == "" || row.Source == "" || row.Network != "solana-mainnet" {
		t.Fatalf("incomplete serious-claim evidence row: %#v", row)
	}
}
