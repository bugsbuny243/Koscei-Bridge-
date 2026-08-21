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
		"Protect the transaction before the signature.",
		"See the execution.",
		"Execution Proof",
		"Transaction Defense",
		"Node Shield",
		"id=\"cross-chain\"",
		"Chain-native evidence, one decision model.",
		"Security Operations",
		"NO VALID PROOF = NO SIGNATURE",
		"Production enforcement is not yet enabled.",
		"Fail closed by design.",
		"koschei-enterprise-v3.css",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("homepage missing Koschei Web3 product identity %q", required)
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
		"STATIC HTML + VANILLA JS",
		"Core available",
		"Adapter planned",
		"Expansion path",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("homepage regressed or introduced a demo/competing product identity: found %q", forbidden)
		}
	}
}
