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

type productionSnapshotFixture struct {
	SchemaVersion  string `json:"schema_version"`
	Target         string `json:"target"`
	Network        string `json:"network"`
	Endpoint       string `json:"endpoint"`
	SourceDecision struct {
		Grade           string `json:"grade"`
		Verdict         string `json:"verdict"`
		Signed          bool   `json:"signed"`
		Signature       string `json:"signature"`
		RulesetVersion  string `json:"ruleset_version"`
		ActorRuleset    string `json:"actor_ruleset"`
		HasLiveEvidence bool   `json:"has_live_evidence"`
	} `json:"source_decision"`
	Interpretation struct {
		Grade                        string   `json:"grade"`
		GradeDeterminingRuleCount    int      `json:"grade_determining_rule_count"`
		GradeDeterminingRuleIDs      []string `json:"grade_determining_rule_ids"`
		SupportingEvidenceGroupCount int      `json:"supporting_evidence_group_count"`
		DistinctCompoundingRuleCount int      `json:"distinct_compounding_rule_count"`
		DistinctCompoundingRuleIDs   []string `json:"distinct_compounding_rule_ids"`
		CorrectedRuleset             string   `json:"corrected_ruleset"`
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
	GradeDetermining []productionFindingFixture `json:"grade_determining_findings"`
	Supporting       []productionFindingFixture `json:"supporting_rule_groups"`
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

type productionFindingFixture struct {
	RuleID         string         `json:"rule_id"`
	EvidenceStatus string         `json:"evidence_status"`
	GradeEffect    string         `json:"grade_effect"`
	EvidenceKeys   []string       `json:"evidence_keys"`
	Facts          map[string]any `json:"facts"`
	EvidenceFile   string         `json:"evidence_file"`
}

type productionEvidenceRowFixture struct {
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

func TestProductionEvidenceSnapshot(t *testing.T) {
	root := filepath.Join("..", "..", "evidence", "production-full-scan")
	raw := readProductionEvidenceFile(t, filepath.Join(root, "2026-08-03-kosch.json"))
	assertProductionEvidenceHasNoSecrets(t, raw)

	var snapshot productionSnapshotFixture
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("decode production snapshot: %v", err)
	}

	if snapshot.SchemaVersion != "koschei-production-evidence-snapshot-v2" {
		t.Fatalf("schema version=%q", snapshot.SchemaVersion)
	}
	if snapshot.Target != "HHPpU9u56Bwxov12nf7DXUCuv6h1q5j1xgGS3yukpump" || snapshot.Network != "solana-mainnet" || snapshot.Endpoint != "/api/token/scan" {
		t.Fatalf("target contract drifted: target=%q network=%q endpoint=%q", snapshot.Target, snapshot.Network, snapshot.Endpoint)
	}
	if snapshot.SourceDecision.Grade != "F" || snapshot.SourceDecision.Verdict != "hard_trigger" || !snapshot.SourceDecision.Signed || snapshot.SourceDecision.Signature == "" || !snapshot.SourceDecision.HasLiveEvidence {
		t.Fatalf("source decision incomplete: %#v", snapshot.SourceDecision)
	}
	if snapshot.SourceDecision.RulesetVersion != "koschei-unified-radar-rules-v1.1.0" || snapshot.SourceDecision.ActorRuleset != services.ActorDefenseRulesetVersion {
		t.Fatalf("source ruleset provenance drifted: %#v", snapshot.SourceDecision)
	}

	interpretation := snapshot.Interpretation
	if interpretation.Grade != "F" || interpretation.GradeDeterminingRuleCount != 1 || interpretation.SupportingEvidenceGroupCount != 4 || interpretation.DistinctCompoundingRuleCount != 1 {
		t.Fatalf("corrected grading semantics missing: %#v", interpretation)
	}
	if strings.Join(interpretation.GradeDeterminingRuleIDs, ",") != services.UnifiedRuleOwnerConcentration || strings.Join(interpretation.DistinctCompoundingRuleIDs, ",") != services.ActorRuleCompoundRepeatedTransfer || interpretation.CorrectedRuleset != services.UnifiedRadarRulesetVersionV110 {
		t.Fatalf("corrected rule identity drifted: %#v", interpretation)
	}

	coverage := snapshot.Coverage
	if coverage.ArchitectureArmCount != 14 || len(coverage.ModuleStates) != 14 || coverage.Observed != 9 || coverage.Pending != 3 || coverage.NotApplicable != 2 || coverage.CoveragePercent != 75 || coverage.CoverageIsRiskScore {
		t.Fatalf("evidence coverage drifted: %#v", coverage)
	}
	pending := make([]string, 0, coverage.Pending)
	for moduleID, state := range coverage.ModuleStates {
		if state == "pending" {
			pending = append(pending, moduleID)
		}
	}
	sort.Strings(pending)
	if strings.Join(pending, ",") != "claim_surface_risk,holder_concentration,walletless_claim_shield" {
		t.Fatalf("pending arms=%v", pending)
	}

	if len(snapshot.GradeDetermining) != 1 {
		t.Fatalf("grade-determining finding count=%d", len(snapshot.GradeDetermining))
	}
	gradeFinding := snapshot.GradeDetermining[0]
	if gradeFinding.RuleID != services.UnifiedRuleOwnerConcentration || gradeFinding.EvidenceStatus != "verified" || gradeFinding.GradeEffect != "hard_cap_F" {
		t.Fatalf("grade-determining finding=%#v", gradeFinding)
	}
	metrics, _ := gradeFinding.Facts["metrics"].(map[string]any)
	share, _ := metrics["owner_resolved_top_share_pct"].(float64)
	if math.Abs(share-99.2987) >= 0.0001 {
		t.Fatalf("owner-resolved share=%f", share)
	}
	if gradeFinding.EvidenceFile == "" {
		t.Fatal("grade-determining URD-C005 finding has no permanent evidence file")
	}

	allRows := map[string]productionEvidenceRowFixture{}
	gradeRaw := readProductionEvidenceFile(t, filepath.Join(root, filepath.FromSlash(gradeFinding.EvidenceFile)))
	assertProductionEvidenceHasNoSecrets(t, gradeRaw)
	var concentrationEvidence struct {
		RuleID               string `json:"rule_id"`
		VerificationStatus   string `json:"verification_status"`
		StateObservationHash string `json:"state_observation_hash"`
		StateSnapshot        struct {
			ObservedAt               string   `json:"observed_at"`
			SourceMethods            []string `json:"source_methods"`
			SourceArtifactSHA256     string   `json:"source_artifact_sha256"`
			Mint                     string   `json:"mint"`
			TokenAccount             string   `json:"token_account"`
			OwnerWallet              string   `json:"owner_wallet"`
			OwnerProgram             string   `json:"owner_program"`
			Balance                  float64  `json:"balance"`
			CirculatingSupply        float64  `json:"circulating_supply"`
			OwnerResolvedTopSharePct float64  `json:"owner_resolved_top_share_pct"`
			VerificationStatus       string   `json:"verification_status"`
		} `json:"state_snapshot"`
		CorroboratingRows []productionEvidenceRowFixture `json:"corroborating_evidence_rows"`
	}
	if err := json.Unmarshal(gradeRaw, &concentrationEvidence); err != nil {
		t.Fatalf("decode %s: %v", gradeFinding.EvidenceFile, err)
	}
	state := concentrationEvidence.StateSnapshot
	if concentrationEvidence.RuleID != services.UnifiedRuleOwnerConcentration || concentrationEvidence.VerificationStatus != "verified" || !strings.HasPrefix(concentrationEvidence.StateObservationHash, "sha256:") || state.ObservedAt == "" || len(state.SourceMethods) < 3 || len(state.SourceArtifactSHA256) != 64 || state.Mint != snapshot.Target || state.TokenAccount == "" || state.OwnerWallet == "" || state.OwnerProgram == "" || state.Balance <= 0 || state.CirculatingSupply <= 0 || math.Abs(state.OwnerResolvedTopSharePct-99.2987) >= 0.0001 || state.VerificationStatus != "verified_state_snapshot" {
		t.Fatalf("incomplete URD-C005 state evidence: %#v", concentrationEvidence)
	}
	if len(concentrationEvidence.CorroboratingRows) != 3 {
		t.Fatalf("URD-C005 corroborating rows=%d", len(concentrationEvidence.CorroboratingRows))
	}
	for _, row := range concentrationEvidence.CorroboratingRows {
		assertCompleteProductionEvidenceRow(t, row)
		if _, duplicate := allRows[row.EvidenceKey]; duplicate {
			t.Fatalf("duplicate grade evidence key %s", row.EvidenceKey)
		}
		allRows[row.EvidenceKey] = row
	}
	for _, evidenceKey := range gradeFinding.EvidenceKeys {
		if strings.HasPrefix(evidenceKey, "state:sha256:") {
			continue
		}
		if _, exists := allRows[evidenceKey]; !exists {
			t.Fatalf("URD-C005 missing complete evidence row %s", evidenceKey)
		}
	}

	if len(snapshot.Supporting) != 4 {
		t.Fatalf("supporting evidence groups=%d", len(snapshot.Supporting))
	}
	for _, group := range snapshot.Supporting {
		if group.RuleID != services.ActorRuleCompoundRepeatedTransfer || group.EvidenceStatus != "verified" || group.GradeEffect != "supporting_context" || group.EvidenceFile == "" {
			t.Fatalf("supporting group semantics=%#v", group)
		}
		rows := readProductionEvidenceRows(t, filepath.Join(root, filepath.FromSlash(group.EvidenceFile)))
		for _, row := range rows {
			assertCompleteProductionEvidenceRow(t, row)
			if _, duplicate := allRows[row.EvidenceKey]; duplicate {
				t.Fatalf("duplicate evidence key %s", row.EvidenceKey)
			}
			allRows[row.EvidenceKey] = row
		}
		for _, evidenceKey := range group.EvidenceKeys {
			if _, exists := allRows[evidenceKey]; !exists {
				t.Fatalf("%s missing complete evidence row %s", group.EvidenceFile, evidenceKey)
			}
		}
	}
	if len(allRows) != 15 {
		t.Fatalf("permanent complete evidence rows=%d", len(allRows))
	}

	if snapshot.Unresolved.Count != 6 || snapshot.Live.Status != "complete" || snapshot.Live.WalletsRequested != 4 || snapshot.Live.WalletsCompleted != 4 || snapshot.Live.SignaturesSeen != 97 || snapshot.Live.TransactionsParsed != 43 || snapshot.Live.RelevantTransactions != 16 || snapshot.Live.RPCFailures != 0 || snapshot.Actor.RunStatus != "partial" {
		t.Fatalf("production counts drifted: unresolved=%d live=%#v actor=%#v", snapshot.Unresolved.Count, snapshot.Live, snapshot.Actor)
	}
	if snapshot.Provenance.ProductionCommit != "bac03e410ee366617cfcc5a7c421f733f5450a9d" || snapshot.Provenance.InterpretationPath != "authoritative_interpretation" {
		t.Fatalf("provenance drifted: %#v", snapshot.Provenance)
	}
	for name, value := range map[string]string{
		"artifact_digest":                  snapshot.Provenance.ArtifactDigest,
		"source_full_scan_response_sha256": snapshot.Provenance.SourceFullScanResponseSHA256,
		"source_full_scan_result_sha256":   snapshot.Provenance.SourceFullScanResultSHA256,
	} {
		if !strings.HasPrefix(value, "sha256:") && len(value) != 64 {
			t.Fatalf("%s is not sha256: %q", name, value)
		}
	}
}

func TestCanonicalVerdictSynchronizationRunsBeforeSnapshotDiagnostics(t *testing.T) {
	actor := services.ActorDefenseRuleVerdict{
		RulesetVersion: services.ActorDefenseRulesetVersion,
		TriggeredRules: repeatedTransferGroupsV111(4),
		WatchFlags:     []services.ActorDefenseRuleHit{},
	}
	behavior := ownerConcentrationBehaviorV111()
	report := map[string]any{
		"target":  "MintSync111",
		"network": "solana-mainnet",
		"final_verdict": services.UnifiedRadarVerdict{
			Grade:          "B",
			Verdict:        "compounding_rule",
			Signed:         true,
			Signature:      "stale-b",
			RulesetVersion: "koschei-unified-radar-rules-v1.1.0",
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
		t.Fatalf("stale verdict survived pre-snapshot synchronization: %#v", final)
	}
	decisionPath := strings.Join(final.DecisionPath, "\n")
	if strings.Contains(decisionPath, "5 distinct") || !strings.Contains(decisionPath, "only one distinct compounding rule ID") {
		t.Fatalf("incorrect synchronized decision path: %s", decisionPath)
	}
}

func TestCustomerAnalysisSummaryV3SeparatesDeterminingAndSupportingFindings(t *testing.T) {
	actor := services.ActorDefenseRuleVerdict{
		RulesetVersion: services.ActorDefenseRulesetVersion,
		TriggeredRules: repeatedTransferGroupsV111(4),
		WatchFlags:     []services.ActorDefenseRuleHit{},
	}
	behavior := ownerConcentrationBehaviorV111()
	final := services.EvaluateUnifiedRadarVerdictV110("MintSummary111", actor, behavior)
	summary := buildCustomerAnalysisSummaryV3(unifiedInvestigationAssembly{
		UnifiedVerdict: final,
		Behavior:       behavior,
	}, true)

	if summary["schema_version"] != customerAnalysisSummarySchemaVersionV3 {
		t.Fatalf("summary schema=%v", summary["schema_version"])
	}
	determining, _ := summary["grade_changing_findings"].([]map[string]any)
	supporting, _ := summary["supporting_findings"].([]map[string]any)
	groups, _ := summary["triggered_evidence_groups"].([]map[string]any)
	decision, _ := summary["decision"].(map[string]any)
	if len(determining) != 1 || determining[0]["rule_id"] != services.UnifiedRuleOwnerConcentration || len(supporting) != 4 || len(groups) != 5 {
		t.Fatalf("v3 classification incorrect: determining=%#v supporting=%#v groups=%#v", determining, supporting, groups)
	}
	if decision["grade_determining_rule_count"] != 1 || decision["distinct_compounding_rule_count"] != 1 || decision["triggered_evidence_group_count"] != 5 {
		t.Fatalf("v3 decision counts=%#v", decision)
	}
}

func repeatedTransferGroupsV111(count int) []services.ActorDefenseRuleHit {
	groups := make([]services.ActorDefenseRuleHit, 0, count)
	for i := 0; i < count; i++ {
		groups = append(groups, services.ActorDefenseRuleHit{
			RuleID:         services.ActorRuleCompoundRepeatedTransfer,
			Title:          "Repeated direct transfer relation",
			Tier:           "compounding",
			EvidenceStatus: "verified",
			GradeEffect:    "compounding_input",
			Count:          i + 2,
			Summary:        "separate evidence group from the same deterministic rule",
			EvidenceKeys:   []string{"evidence-key"},
			Signatures:     []string{"signature"},
		})
	}
	return groups
}

func ownerConcentrationBehaviorV111() services.UnifiedRadarBehaviorReport {
	return services.UnifiedRadarBehaviorReport{
		RulesetVersion: services.UnifiedRadarRulesetVersionV110,
		Signals: []services.UnifiedRadarSignal{
			{
				RuleID:         services.UnifiedRuleOwnerConcentration,
				Title:          "Owner-resolved dominant concentration",
				EvidenceStatus: "verified",
				Triggered:      true,
				GradeEffect:    "hard_cap_F",
				Scope:          "owner_resolved_infrastructure_excluded_circulating_supply",
				Summary:        "Owner-resolved top ownership met the F-cap threshold.",
				Metrics:        map[string]any{"owner_resolved_top_share_pct": 99.2987},
				Thresholds:     map[string]any{"f_cap_pct": 70.0},
				EvidenceKeys:   []string{"owner:dominant"},
				Signatures:     []string{},
				Limitations:    []string{},
				ObservedAt:     time.Now().UTC(),
			},
		},
		GeneratedAt: time.Now().UTC(),
	}
}

func readProductionEvidenceRows(t *testing.T, path string) []productionEvidenceRowFixture {
	t.Helper()
	raw := readProductionEvidenceFile(t, path)
	assertProductionEvidenceHasNoSecrets(t, raw)
	var document struct {
		RuleID       string                         `json:"rule_id"`
		EvidenceRows []productionEvidenceRowFixture `json:"evidence_rows"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if document.RuleID != services.ActorRuleCompoundRepeatedTransfer {
		t.Fatalf("%s rule=%q", path, document.RuleID)
	}
	return document.EvidenceRows
}

func readProductionEvidenceFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

func assertProductionEvidenceHasNoSecrets(t *testing.T, raw []byte) {
	t.Helper()
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{
		`"authorization"`,
		`"cookie"`,
		`"set-cookie"`,
		`"password"`,
		`"database_url"`,
		`"alchemy_api_key"`,
		`"private_key"`,
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("evidence contains forbidden secret-like field %s", forbidden)
		}
	}
}

func assertCompleteProductionEvidenceRow(t *testing.T, row productionEvidenceRowFixture) {
	t.Helper()
	if row.EvidenceKey == "" || row.Signature == "" || row.Slot <= 0 || row.Timestamp == "" || row.SourceWallet == "" || row.DestinationWallet == "" || len(row.Amount) == 0 || row.Program == "" || row.Verification != "verified" || row.Relation == "" || row.Source == "" || row.Network != "solana-mainnet" {
		t.Fatalf("incomplete serious-claim evidence row: %#v", row)
	}
}
