package main

import (
	"os"
	"strings"
	"testing"
)

func TestHomepageKeepsKoscheiWeb3AsEvidenceFirstUniverseGateway(t *testing.T) {
	body, err := os.ReadFile("public/index.html")
	if err != nil {
		t.Fatalf("read homepage: %v", err)
	}
	text := string(body)
	for _, required := range []string{
		"Koschei Web3 | The Universe",
		"Web3 defenses?<br>Who tests them?",
		"data-koschei-home-scan",
		"Solana wallet or token mint",
		"Enter the universe",
		"One address. Full threat context.",
		"Solana is the live production core today.",
		"without inventing certainty",
		"Every material conclusion should descend to evidence",
		"Professional operation · no private keys · no custody · unknown stays unknown",
		"koschei-universe-v1.css",
		"koschei-home-universe-v2.css",
		"koschei-global-shell.js?v=4",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("homepage missing evidence-first Universe contract %q", required)
		}
	}
	for _, forbidden := range []string{
		"Koschei Web3 | Security World",
		">Security World<",
		"SECURITY WORLD / TOPOLOGY",
		"Koschei ARVIS | Evidence-Backed Web3 Security",
		"Open Security Workspace",
		"Review Architecture",
		"NO VALID PROOF = NO SIGNATURE",
		"homepage-score-label",
		"homepage-preflight-v2.js",
		"STATIC HTML + VANILLA JS",
		"Core available",
		"Adapter planned",
		"Expansion path",
		"ETHEREUM</b><small>LIVE",
		"TRON</b><small>LIVE",
		"100% secure",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("homepage regressed into architecture/demo-first or unsupported presentation: found %q", forbidden)
		}
	}
}

func TestHomepageExposesRequiredPaddleDomainReviewPolicies(t *testing.T) {
	body, err := os.ReadFile("public/index.html")
	if err != nil {
		t.Fatalf("read homepage: %v", err)
	}
	text := string(body)
	for _, policyLink := range []string{
		`href="/terms.html">Terms</a>`,
		`href="/privacy.html">Privacy</a>`,
		`href="/refund-policy.html">Refunds</a>`,
	} {
		if !strings.Contains(text, policyLink) {
			t.Fatalf("homepage missing required Paddle domain-review policy link %q", policyLink)
		}
	}
}
