package defense

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestParseAnchorIDLForHarnessSupportsModernAndNestedAccounts(t *testing.T) {
	idl := map[string]any{
		"instructions": []any{
			map[string]any{
				"name":          "withdraw",
				"discriminator": []any{1, 2, 3, 4, 5, 6, 7, 8},
				"accounts": []any{
					map[string]any{"name": "authority", "signer": true},
					map[string]any{"name": "vault", "writable": true, "pda": map[string]any{"seeds": []any{}}},
					map[string]any{"name": "group", "accounts": []any{
						map[string]any{"name": "readonlyState", "isMut": false, "isSigner": false},
					}},
				},
				"args": []any{map[string]any{"name": "amount", "type": "u64"}},
			},
		},
	}
	raw, _ := json.Marshal(idl)
	instructions, count, err := parseAnchorIDLForHarness(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(instructions) != 1 || count != 3 {
		t.Fatalf("unexpected plan grammar: instructions=%d accounts=%d", len(instructions), count)
	}
	instruction := instructions[0]
	if instruction.Name != "withdraw" || len(instruction.Arguments) != 1 || len(instruction.Accounts) != 3 {
		t.Fatalf("unexpected instruction: %+v", instruction)
	}
	accounts := map[string]HarnessAccount{}
	for _, account := range instruction.Accounts {
		accounts[account.Path] = account
	}
	if !accounts["authority"].Signer || !accounts["vault"].Writable || !accounts["vault"].PDA || accounts["group.readonlyState"].Writable {
		t.Fatalf("account flags were not preserved: %+v", accounts)
	}
	templates := buildHarnessInvariantTemplates(instructions)
	for _, kind := range []string{"instruction_no_unexpected_panic", "signer_authorization_template", "readonly_account_unchanged_template", "writable_state_transition_template"} {
		found := false
		for _, template := range templates {
			if template.Kind == kind {
				found = true
				if !template.HumanConfirmationRequired {
					t.Fatalf("template %s did not require human confirmation", kind)
				}
			}
		}
		if !found {
			t.Fatalf("missing invariant template: %s", kind)
		}
	}
}

func TestGenerateHarnessPlanPersistsNonExecutablePlan(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	programID := fmt.Sprintf("CIHarnessProgram%d", time.Now().UnixNano())
	idlRaw, _ := json.Marshal(map[string]any{
		"instructions": []any{map[string]any{
			"name":     "initialize",
			"accounts": []any{map[string]any{"name": "payer", "signer": true, "writable": true}},
			"args":     []any{},
		}},
	})
	artifact, err := StoreArtifact(ctx, db, ArtifactInput{ProgramID: programID, Network: "solana-mainnet", ArtifactType: "anchor_idl",
		ContentEncoding: "json", Content: string(idlRaw), Framework: "anchor", FrameworkVersion: "0.32.1", TrustLevel: "observed", CreatedBy: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := GenerateHarnessPlan(ctx, db, HarnessPlanInput{IDLArtifactRef: artifact.ArtifactRef})
	if err != nil {
		t.Fatal(err)
	}
	if plan.PlanRef == "" || plan.PlanHash == "" || plan.ExecutionReady || !plan.ManualGuidanceRequired || plan.VerdictAuthority {
		t.Fatalf("unexpected harness plan: %+v", plan)
	}
	if plan.InstructionCount != 1 || plan.AccountCount != 1 || len(plan.EngineCandidates) != 2 {
		t.Fatalf("unexpected plan counts: %+v", plan)
	}
	stored, err := ListHarnessPlans(ctx, db, programID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].PlanRef != plan.PlanRef || stored[0].ExecutionReady {
		t.Fatalf("unexpected stored plan: %+v", stored)
	}
}

func TestParseAnchorIDLForHarnessRejectsMissingInstructions(t *testing.T) {
	if _, _, err := parseAnchorIDLForHarness([]byte(`{"metadata":{"name":"empty"}}`)); err == nil {
		t.Fatal("IDL without instructions was accepted")
	}
}
