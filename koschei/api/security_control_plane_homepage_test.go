package main

import (
	"os"
	"strings"
	"testing"
)

func TestHomepageKeepsKoscheiWeb3AsSingleProductBrand(t *testing.T) {
	body, err := os.ReadFile("public/index.html")
	if err != nil {
		t.Fatalf("read homepage: %v", err)
	}
	text := string(body)
	for _, required := range []string{
		"Koschei Web3 | Web3 Security",
		"See the execution.",
		"WEB3 EXECUTION TOPOLOGY",
		"koschei-security-world.js",
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
			t.Fatalf("homepage missing Koschei Web3 identity %q", required)
		}
	}
	for _, forbidden := range []string{
		"Koschei Web3 | Security World",
		">Security World<",
		"SECURITY WORLD / TOPOLOGY",
		"Koschei ARVIS | Evidence-Backed Web3 Security",
		">Token Scan<",
		"Solana-first evidence intelligence",
		"Run a free preflight",
		"Buy a token",
		"homepage-score-label",
		"homepage-preflight-v2.js",
		">Implemented<",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("homepage regressed or introduced a competing product identity: found %q", forbidden)
		}
	}
}
