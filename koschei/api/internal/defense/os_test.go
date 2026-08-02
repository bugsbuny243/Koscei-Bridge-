package defense

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func sourceArtifact(t *testing.T, source string) Artifact {
	t.Helper()
	bundle, err := json.Marshal(map[string]string{"programs/demo/src/lib.rs": source})
	if err != nil {
		t.Fatal(err)
	}
	return Artifact{ArtifactRef: "KDA1-0123456789abcdef0123456789abcdef", ProgramID: "Demo1111111111111111111111111111111111111", Network: "solana-mainnet", ArtifactType: "source_bundle", ContentHash: hashValue(bundle), Content: bundle, Framework: "anchor", FrameworkVersion: "0.31.1", TrustLevel: "verified", Verified: true}
}

func TestAnalyzeArtifactFindsConservativeSolanaSurfaces(t *testing.T) {
	artifact := sourceArtifact(t, `
#[program]
pub mod demo {
    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
        let _ = ctx.remaining_accounts;
        unsafe { core::ptr::read_volatile(&0); }
        Ok(())
    }
}
#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub authority: UncheckedAccount<'info>,
}
`)
	report, err := AnalyzeArtifact(artifact)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, finding := range report.Findings {
		seen[finding.RuleID] = true
		if finding.VerdictAuthority {
			t.Fatalf("static finding gained verdict authority: %+v", finding)
		}
		if finding.Confidence == "verified" || finding.LifecycleStatus == "reproduced" {
			t.Fatalf("static detector overclaimed: %+v", finding)
		}
	}
	for _, rule := range []string{"KPS-S001", "KPS-S002", "KPS-S004"} {
		if !seen[rule] {
			t.Fatalf("missing expected rule %s: %#v", rule, seen)
		}
	}
	if len(report.Nodes) < 2 || len(report.Edges) == 0 {
		t.Fatalf("program/instruction graph missing: %+v", report)
	}
}

func TestUncheckedAccountWithCheckRationaleIsNotFlagged(t *testing.T) {
	artifact := sourceArtifact(t, `
#[derive(Accounts)]
pub struct Read<'info> {
    /// CHECK: account key and owner are validated in the handler before use.
    pub external: UncheckedAccount<'info>,
}
`)
	report, err := AnalyzeArtifact(artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range report.Findings {
		if finding.RuleID == "KPS-S001" {
			t.Fatalf("CHECK-rationalized account was flagged: %+v", finding)
		}
	}
}

func TestSyntheticMutationNeverBecomesProductionArtifact(t *testing.T) {
	artifact := sourceArtifact(t, `pub struct Withdraw<'info> { pub authority: Signer<'info>, }`)
	candidate, err := SyntheticMutation(artifact, "replace_signer_with_unchecked")
	if err != nil {
		t.Fatal(err)
	}
	if candidate.ArtifactType != "synthetic_source_bundle" || candidate.TrustLevel != "synthetic" || candidate.Verified {
		t.Fatalf("unsafe synthetic classification: %+v", candidate)
	}
	if !strings.Contains(candidate.Content, "UncheckedAccount") {
		t.Fatalf("mutation was not applied: %s", candidate.Content)
	}
	if eligible, _ := candidate.Metadata["production_eligible"].(bool); eligible {
		t.Fatal("synthetic artifact became production eligible")
	}
}

func TestVerifyBundleDisabledExecutesNothing(t *testing.T) {
	artifact := sourceArtifact(t, `pub fn test() {}`)
	report, err := VerifyBundle(context.Background(), artifact, "", "", nil, []string{"cargo test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "blocked" || report.ExecutionMode != "blocked" || report.CanExecuteMainnet {
		t.Fatalf("disabled sandbox contract broken: %+v", report)
	}
	if len(report.Results) != 0 {
		t.Fatalf("command executed while sandbox disabled: %+v", report.Results)
	}
}

func TestSourceBundleRejectsTraversal(t *testing.T) {
	encoded, _ := json.Marshal(map[string]string{"../secret": "x"})
	if _, err := decodeSourceBundle(encoded); err == nil {
		t.Fatal("path traversal was accepted")
	}
}

func TestEvaluateRulesExactEvidenceDiscipline(t *testing.T) {
	passed := EvaluateRules([]string{"KPS-S001"}, []string{"KPS-S003"}, []string{"KPS-S001"})
	if !passed.Passed || passed.Precision != 1 || passed.Recall != 1 {
		t.Fatalf("expected passing benchmark: %+v", passed)
	}
	failed := EvaluateRules([]string{"KPS-S001"}, nil, []string{"KPS-S002"})
	if failed.Passed || failed.FalsePositive != 1 || failed.FalseNegative != 1 {
		t.Fatalf("expected failed benchmark: %+v", failed)
	}
}
