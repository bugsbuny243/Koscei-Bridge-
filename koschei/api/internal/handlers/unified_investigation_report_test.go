package handlers

import (
	"context"
	"encoding/json"
	"testing"

	"koschei/api/internal/services"
)

func TestUnifiedInvestigationTechnicalResultIsCallerNeutral(t *testing.T) {
	ref := 125000.0
	core := holderIntelligenceCoreResult{
		Request: services.SecurityRadarRequest{Target: "MintParity111111111111111111111111111111111", Network: "solana-mainnet", Mode: "fixture"},
		Arms: []services.SecurityRadarVerdict{
			{Module: "Token Authority Scanner", ModuleID: services.ModuleTokenAuthorityScanner, Signed: true, Signals: map[string]any{"real_onchain_evidence": true, "execution_status": services.ArvisExecutionCompleted, "mint_authority_present": false, "freeze_authority_present": false}, Evidence: []string{"authority parsed"}},
			{Module: "Holder Concentration", ModuleID: services.ModuleHolderConcentration, Signed: true, Signals: map[string]any{"real_onchain_evidence": true, "execution_status": services.ArvisExecutionCompleted, "owner_resolved_top_holder_pct": 36.0}, Evidence: []string{"owner resolved"}},
		},
		Distribution:    map[string]any{"available": true, "top_1_percentage": 36.0},
		Market:          services.TokenMarketSnapshot{Available: true, Mint: "MintParity111111111111111111111111111111111", LiquidityUSD: 50000},
		Intelligence:    services.HolderIntelligence{Available: true, Status: "evidence_backed", CirculatingSupply: 1000000, TopOwnerPercentage: 36, TopOwnerBalance: 360000, TopOwnerReferenceUSDValue: &ref, Rows: []services.HolderIntelligenceRow{}, Findings: []string{}, Limitations: []string{}},
		Cluster:         services.HolderClusterAnalysis{Findings: []string{}},
		LaunchForensics: services.LaunchForensicsAnalysis{Available: true, Status: "observed", Findings: []string{}, Limitations: []string{}},
		SourceContext:   map[string]any{"creator_wallet": "CreatorParity111111111111111111111111111111"},
	}
	h := &Handler{}
	assembly := h.assembleUnifiedInvestigationReport(context.Background(), core)
	ownerProjection := unifiedInvestigationTechnicalProjection(assembly.Report)
	publicEnvelope := map[string]any{"investigation_report": assembly.Report, "score": 50}
	publicProjection := unifiedInvestigationTechnicalProjection(publicEnvelope["investigation_report"].(map[string]any))
	apiResult := customerTokenScanResult{InvestigationReport: assembly.Report}
	apiProjection := unifiedInvestigationTechnicalProjection(apiResult.InvestigationReport)

	ownerJSON, _ := json.Marshal(ownerProjection)
	publicJSON, _ := json.Marshal(publicProjection)
	apiJSON, _ := json.Marshal(apiProjection)
	if string(ownerJSON) != string(publicJSON) || string(ownerJSON) != string(apiJSON) {
		t.Fatalf("technical investigation differs by caller\nowner=%s\npublic=%s\napi=%s", ownerJSON, publicJSON, apiJSON)
	}
	if _, exists := ownerProjection["generated_at"]; exists {
		t.Fatal("request timestamp leaked into canonical technical projection")
	}
	policy, ok := ownerProjection["investigation_output_policy"].(services.InvestigationOutputPolicy)
	if !ok || !policy.SameTechnicalResult {
		t.Fatalf("caller-neutral policy missing: %#v", ownerProjection["investigation_output_policy"])
	}
}

func TestUnifiedInvestigationStoredOnlyKeepsActorCollectorsRPCFree(t *testing.T) {
	core := holderIntelligenceCoreResult{
		Request: services.SecurityRadarRequest{
			Target:  "MintStoredOnly11111111111111111111111111111",
			Network: "solana-mainnet",
			Mode:    "stored_only_projection",
		},
		SourceContext: map[string]any{
			"creator_wallet": "CreatorStoredOnly111111111111111111111111111",
		},
		Cluster: services.HolderClusterAnalysis{Findings: []string{}},
	}

	assembly := (&Handler{}).assembleUnifiedInvestigationReport(context.Background(), core)
	actor, ok := assembly.Report["actor_investigation"].(map[string]any)
	if !ok {
		t.Fatalf("actor investigation section missing: %#v", assembly.Report["actor_investigation"])
	}
	run, ok := actor["integration_run"].(unifiedActorInvestigationRun)
	if !ok {
		t.Fatalf("actor integration run missing: %#v", actor["integration_run"])
	}
	if run.LiveRequested {
		t.Fatal("stored-only projection requested live actor evidence")
	}
	if run.LiveEvidence.Status != "not_requested" {
		t.Fatalf("stored-only projection changed live actor status: %s", run.LiveEvidence.Status)
	}
}

func TestUnifiedInvestigationLiveModeMarksMissingCreatorExplicitly(t *testing.T) {
	core := holderIntelligenceCoreResult{
		Request: services.SecurityRadarRequest{
			Target:  "MintWithoutCreator111111111111111111111111111",
			Network: "solana-mainnet",
			Mode:    "owner_unified_manual_scan",
		},
		SourceContext: map[string]any{},
		Cluster:       services.HolderClusterAnalysis{Findings: []string{}},
	}

	assembly := (&Handler{}).assembleUnifiedInvestigationReport(context.Background(), core)
	actor := assembly.Report["actor_investigation"].(map[string]any)
	run := actor["integration_run"].(unifiedActorInvestigationRun)
	if !run.LiveRequested {
		t.Fatal("live unified scan did not request actor investigation")
	}
	if run.Status != "creator_unavailable" {
		t.Fatalf("missing creator should be explicit, got %q", run.Status)
	}
	if len(run.Limitations) == 0 {
		t.Fatal("missing creator did not produce an investigation limitation")
	}
}

func TestUnifiedInvestigationProjectsCreatorFieldsFromCanonicalActorResult(t *testing.T) {
	creator := "CreatorProjection1111111111111111111111111111"
	core := holderIntelligenceCoreResult{
		Request: services.SecurityRadarRequest{
			Target:  "MintProjection111111111111111111111111111111",
			Network: "solana-mainnet",
			Mode:    "stored_only_projection",
		},
		SourceContext: map[string]any{"creator_wallet": creator},
		Cluster:       services.HolderClusterAnalysis{Findings: []string{}},
	}

	assembly := (&Handler{}).assembleUnifiedInvestigationReport(context.Background(), core)
	intelligence, ok := assembly.Report["creator_intelligence"].(map[string]any)
	if !ok {
		t.Fatalf("creator_intelligence projection missing: %#v", assembly.Report["creator_intelligence"])
	}
	if !dossierBool(intelligence["available"]) || dossierString(intelligence["creator_wallet"]) != creator {
		t.Fatalf("creator_intelligence projection invalid: %#v", intelligence)
	}
	if _, exists := intelligence["integration_run"]; !exists {
		t.Fatalf("creator_intelligence lost canonical integration run: %#v", intelligence)
	}
	distribution, ok := assembly.Report["creator_distribution"].(map[string]any)
	if !ok {
		t.Fatalf("creator_distribution projection missing: %#v", assembly.Report["creator_distribution"])
	}
	if dossierString(distribution["status"]) != "not_requested" || dossierBool(distribution["available"]) {
		t.Fatalf("stored-only distribution projection should remain unavailable: %#v", distribution)
	}
}
