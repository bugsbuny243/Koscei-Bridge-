package handlers

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExitImpactV2ReachableFromCanonicalHolderInvestigation(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve current test file")
	}
	sourcePath := filepath.Join(filepath.Dir(currentFile), "holder_intelligence_core.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	for _, required := range []string{
		"exitLiquidity = h.collectExitLiquiditySimulation",
		"exitLiquidity.ImpactV2 = services.BuildExitImpactAssessment(exitLiquidity, lpControl)",
		"jupiter.ExitLiquidity = exitLiquidity",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("canonical investigation no longer wires Exit Impact v2: missing %q", required)
		}
	}
	if strings.Index(body, "collectCompleteLPControlEvidence") > strings.Index(body, "BuildExitImpactAssessment") {
		t.Fatal("Exit Impact v2 must be built only after LP-control evidence is collected")
	}
}
