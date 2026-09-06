package main

import (
	"os"
	"strings"
	"testing"
)

func TestHomepageKeepsKoscheiWeb3AsSingleCustomerFirstProduct(t *testing.T) {
	body, err := os.ReadFile("public/index.html")
	if err != nil {
		t.Fatalf("read homepage: %v", err)
	}
	text := string(body)
	for _, required := range []string{
		"Koschei Web3 | Check before you trust",
		"Check it before you trust it.",
		"data-koschei-home-scan",
		"Token mint, wallet, site URL, or transaction context",
		"One scan. Four questions answered.",
		"Should I proceed?",
		"What changed the decision?",
		"Can I verify it?",
		"id=\"execution-proof\"",
		"The proof still matters.",
		"Production signing enforcement remains a separate validation milestone",
		"Koschei Professional is the single paid access plan.",
		"koschei-enterprise-v3.css",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("homepage missing customer-first Koschei Web3 contract %q", required)
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
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("homepage regressed into architecture/demo-first presentation: found %q", forbidden)
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
