package main

import (
	"os"
	"strings"
	"testing"
)

func TestPiCustomerScanRoutesBeforeSolanaCollectors(t *testing.T) {
	body, err := os.ReadFile("public/js/public-solana-scan.js")
	if err != nil {
		t.Fatalf("read customer scan runtime: %v", err)
	}
	scan := string(body)
	for _, required := range []string{
		"isLikelyPiAccount",
		"isLikelyPiAsset",
		"isLikelyPiTarget",
		"/api/security/radar/check",
		"network:'pi-testnet'",
		"renderPiTechnicalReport",
		"PI TESTNET EVIDENCE FILE",
		"GRADE WITHHELD",
		"UNKNOWN is not SAFE",
		"signed grade disabled",
	} {
		if !strings.Contains(scan, required) {
			t.Fatalf("Pi customer scan runtime missing %q", required)
		}
	}

	piBranch := strings.Index(scan, "if(piTarget){")
	solanaTokenBranch := strings.Index(scan, "}else if(tokenScan){")
	if piBranch < 0 || solanaTokenBranch < 0 || piBranch >= solanaTokenBranch {
		t.Fatal("Pi targets must be diverted before the Solana token collector")
	}

	start := strings.Index(scan, "function renderPiTechnicalReport")
	end := strings.Index(scan, "function renderPreflight")
	if start < 0 || end <= start {
		t.Fatal("Pi evidence renderer boundary missing")
	}
	piRenderer := scan[start:end]
	for _, forbidden := range []string{"/100", "risk_index", "solscan.io", "SIGNED TECHNICAL REPORT"} {
		if strings.Contains(piRenderer, forbidden) {
			t.Fatalf("Pi evidence renderer must not invent Solana/scored verdict semantics: found %q", forbidden)
		}
	}
}
