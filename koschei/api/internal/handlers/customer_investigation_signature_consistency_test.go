package handlers

import (
	"encoding/json"
	"fmt"
	"testing"

	"koschei/api/internal/services"
)

func TestCustomerInvestigationEnvelopeSerializesOneCanonicalVerdictSignature(t *testing.T) {
	final := services.FinalizeUnifiedRadarVerdictContract("MintSignature111", services.UnifiedRadarVerdict{
		RulesetVersion: services.UnifiedRadarRulesetVersion,
		ActorRuleset:   services.ActorDefenseRulesetVersion,
		TriggeredRules: []services.ActorDefenseRuleHit{
			{RuleID: services.ActorRuleCompoundCreatorReuse, Tier: "compounding", EvidenceStatus: "verified", Summary: "creator reuse"},
			{RuleID: services.UnifiedRuleVolumeLiquidityGap, Tier: "compounding", EvidenceStatus: "observed", Summary: "market gap"},
		},
	})
	assembly := unifiedInvestigationAssembly{
		Report: map[string]any{
			"ok":             true,
			"schema_version": unifiedInvestigationSchemaVersion,
			"target":         "MintSignature111",
			"final_verdict":  final,
		},
		Core: holderIntelligenceCoreResult{
			Request: services.SecurityRadarRequest{Target: "MintSignature111", Network: "solana-mainnet"},
		},
		UnifiedVerdict: final,
	}

	envelope := customerInvestigationEnvelope(assembly, false)
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}

	top := testSignatureFromMap(t, decoded, "final_verdict")
	report, ok := decoded["investigation_report"].(map[string]any)
	if !ok {
		t.Fatalf("investigation_report=%T", decoded["investigation_report"])
	}
	nested := testSignatureFromMap(t, report, "final_verdict")
	summary, ok := decoded["analysis_summary"].(map[string]any)
	if !ok {
		t.Fatalf("analysis_summary=%T", decoded["analysis_summary"])
	}
	decision, ok := summary["decision"].(map[string]any)
	if !ok {
		t.Fatalf("analysis_summary.decision=%T", summary["decision"])
	}
	decisionSignature := fmt.Sprint(decision["signature"])

	if top != final.Signature || nested != final.Signature || decisionSignature != final.Signature {
		t.Fatalf("canonical signature drift: finalized=%q top=%q nested=%q decision=%q\n%s", final.Signature, top, nested, decisionSignature, raw)
	}
}

func testSignatureFromMap(t *testing.T, parent map[string]any, key string) string {
	t.Helper()
	value, ok := parent[key].(map[string]any)
	if !ok {
		t.Fatalf("%s=%T", key, parent[key])
	}
	return fmt.Sprint(value["signature"])
}
