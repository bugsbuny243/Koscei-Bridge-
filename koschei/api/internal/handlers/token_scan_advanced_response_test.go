package handlers

import (
	"encoding/json"
	"reflect"
	"testing"

	"koschei/api/internal/services"
)

func TestAttachCustomerAnalysisSummaryMutatesCanonicalReport(t *testing.T) {
	assembly := unifiedInvestigationAssembly{
		Report: map[string]any{
			"ok":             true,
			"schema_version": unifiedInvestigationSchemaVersion,
		},
		Core: holderIntelligenceCoreResult{
			Request: services.SecurityRadarRequest{Target: "Mint444", Network: "solana-mainnet"},
			Arms: []services.SecurityRadarVerdict{
				{
					ModuleID: "token_authority_scanner",
					Module:   "Token Authority Scanner",
					Signed:   true,
					Signals:  map[string]any{"evidence_status": "verified", "verified_evidence": true},
					Evidence: []string{"mint-authority:closed"},
				},
			},
			Bundle: services.SecurityRadarBundle{
				Metadata: map[string]any{
					"arvis_arms": []services.SecurityRadarVerdict{
						{
							ModuleID: "token_authority_scanner",
							Module:   "Token Authority Scanner",
							Signed:   true,
							Signals:  map[string]any{"verified_evidence": true},
							Evidence: []string{"mint-authority:closed"},
						},
					},
				},
			},
		},
		UnifiedVerdict: services.UnifiedRadarVerdict{
			Grade:   "B",
			Verdict: "evidence_backed",
			Signed:  true,
		},
	}

	summary := attachCustomerAnalysisSummary(&assembly)
	if summary["schema_version"] != customerAnalysisSummarySchemaVersionV3 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	if !reflect.DeepEqual(assembly.Report["analysis_summary"], summary) {
		t.Fatalf("canonical report did not receive the shared summary: %#v", assembly.Report)
	}
}

func TestTokenScanResponseExposesV3ContractAndSummaryAtBothLevels(t *testing.T) {
	summary := map[string]any{
		"schema_version": customerAnalysisSummarySchemaVersionV3,
		"decision": map[string]any{
			"grade":             "F",
			"signed":            true,
			"ruleset_version":   services.UnifiedRadarRulesetVersionV110,
			"grading_semantics": "distinct_rule_ids_not_evidence_group_count",
		},
		"grade_changing_findings": []map[string]any{{"rule_id": services.UnifiedRuleOwnerConcentration}},
		"supporting_findings":     []map[string]any{{"rule_id": services.ActorRuleCompoundRepeatedTransfer}},
	}
	response := tokenScanResponse{
		Mint:            "Mint555",
		Network:         "solana-mainnet",
		AnalysisSummary: summary,
		InvestigationReport: map[string]any{
			"target":           "Mint555",
			"analysis_summary": summary,
		},
	}

	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal token scan response: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode token scan response: %v", err)
	}
	if decoded["response_schema_version"] != customerInvestigationResponseSchemaVersion {
		t.Fatalf("response schema missing: %#v", decoded)
	}
	top, ok := decoded["analysis_summary"].(map[string]any)
	if !ok || top["schema_version"] != customerAnalysisSummarySchemaVersionV3 {
		t.Fatalf("top-level v3 summary missing: %#v", decoded)
	}
	if supporting, ok := top["supporting_findings"].([]any); !ok || len(supporting) != 1 {
		t.Fatalf("supporting findings missing from top-level summary: %#v", top)
	}
	report, ok := decoded["investigation_report"].(map[string]any)
	if !ok {
		t.Fatalf("investigation report missing: %#v", decoded)
	}
	nested, ok := report["analysis_summary"].(map[string]any)
	if !ok || nested["schema_version"] != customerAnalysisSummarySchemaVersionV3 {
		t.Fatalf("nested v3 summary missing: %#v", report)
	}
}
