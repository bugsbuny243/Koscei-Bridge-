package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTransactionGuardV3CollectorsReachableFromV2Endpoint(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve current test file")
	}
	sourcePath := filepath.Join(filepath.Dir(currentFile), "transaction_guard_v2_evidence_first.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), sourcePath, source, 0)
	if err != nil {
		t.Fatal(err)
	}

	var endpoint *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "TransactionGuardV2EvidenceFirst" {
			endpoint = function
			break
		}
	}
	if endpoint == nil || endpoint.Body == nil {
		t.Fatal("registered v2 evidence-first endpoint implementation not found")
	}

	calls := map[string]bool{}
	ast.Inspect(endpoint.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch function := call.Fun.(type) {
		case *ast.Ident:
			calls[function.Name] = true
		case *ast.SelectorExpr:
			calls[function.Sel.Name] = true
		}
		return true
	})
	for _, required := range []string{
		"resolveTransactionGuardV3CPIFlow",
		"analyzeTransactionGuardV3AuthoritySurface",
		"collectTransactionGuardV3ThreatHistory",
		"buildTransactionGuardStateWitness",
		"finalizeEvidenceFirstGuardAssessment",
		"finishTransactionGuardV3ResponseWithWitness",
	} {
		if !calls[required] {
			t.Fatalf("v2 evidence-first endpoint no longer calls %s", required)
		}
	}

	body := string(source)
	for _, failClosedGate := range []string{
		"if threatHistory.Required && !threatHistory.Complete",
		"if cpiFlow.Required && !cpiFlow.Complete",
		"if authoritySurface.Required && !authoritySurface.Complete",
	} {
		if !strings.Contains(body, failClosedGate) {
			t.Fatalf("missing fail-closed collector gate %q", failClosedGate)
		}
	}
	for _, stateBinding := range []string{
		"pre.Context.Slot, simulation.Context.Slot, ordered, pre.Value",
		"No bounded pre-state account set was available for state witnessing.",
	} {
		if !strings.Contains(body, stateBinding) {
			t.Fatalf("missing live state witness binding %q", stateBinding)
		}
	}
}

func TestTransactionGuardV3IncompleteCollectorEvidenceWithholds(t *testing.T) {
	assessment := transactionFirewallAssessment{
		Action:       "allow",
		RiskLevel:    "low",
		SimulationOK: true,
		Findings:     []transactionFirewallFinding{},
	}
	result := finalizeEvidenceFirstGuardAssessment(
		assessment,
		transactionGuardProgramPolicy{Complete: true},
		transactionGuardIntentPolicy{Complete: false},
	)
	if result.Action != "withhold" || result.RiskLevel != "unknown" {
		t.Fatalf("incomplete v3 evidence action=%q risk=%q", result.Action, result.RiskLevel)
	}
}
