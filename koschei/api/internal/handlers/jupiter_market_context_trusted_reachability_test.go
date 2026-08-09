package handlers

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTrustedJupiterMarketContextReachableFromCanonicalInvestigation(t *testing.T) {
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
	if !strings.Contains(body, "jupiter = h.collectTrustedJupiterMarketContext(parent, network, target, intelligence, market)") {
		t.Fatal("canonical investigation no longer uses trusted Jupiter market context")
	}
	if strings.Contains(body, "jupiter = h.collectJupiterMarketContext(parent, network, target, intelligence, market)") {
		t.Fatal("canonical investigation fell back to legacy generic Jupiter collector")
	}
}
