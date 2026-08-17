package main

import (
	"os"
	"strings"
	"testing"
)

func TestHomepageIsSecurityControlPlaneNotTokenScanner(t *testing.T) {
	body, err := os.ReadFile("public/index.html")
	if err != nil {
		t.Fatalf("read homepage: %v", err)
	}
	text := string(body)
	for _, required := range []string{
		"Koschei Web3 | Security Control Plane",
		"Prove what will execute.",
		"Execution Proof",
		"Transaction Defense",
		"Node Shield",
		"Cross-Chain Trust",
		"Security Operations",
		"NO VALID PROOF = NO SIGNATURE",
		"Core available",
		"In validation",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("homepage missing control-plane identity %q", required)
		}
	}
	for _, forbidden := range []string{
		">Token Scan<",
		"Solana-first evidence intelligence",
		"Run a free preflight",
		"Buy a token",
		"homepage-score-label",
		"Koschei ARVIS | Evidence-Backed Web3 Security",
		"homepage-preflight-v2.js",
		">Implemented<",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("homepage regressed or overclaimed product status: found %q", forbidden)
		}
	}
}
