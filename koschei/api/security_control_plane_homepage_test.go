package main

import (
	"os"
	"strings"
	"testing"
)

func TestHomepageKeepsKoscheiWeb3AsTwoSurfaceEvidenceFirstGateway(t *testing.T) {
	body, err := os.ReadFile("public/index.html")
	if err != nil {
		t.Fatalf("read homepage: %v", err)
	}
	text := string(body)
	for _, required := range []string{
		"Koschei Web3 | Security Validation & Risk Intelligence",
		"See the blind spot.",
		"Before it becomes the attack.",
		"missing evidence stays unknown",
		"Solana live production core",
		"Address",
		"Transaction",
		"Entity",
		"Attack Path",
		"Evidence",
		"More than a scanner.",
		"Protocol Defense Validation",
		"Cross-chain Intelligence",
		"STRUCTURE ONLY · NOT LIVE TELEMETRY",
		"Customer Panel",
		`href="/dashboard"`,
		`href="/css/koschei-home.css?v=1"`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("homepage missing two-surface evidence contract %q", required)
		}
	}
	if got := strings.Count(text, `<link rel="stylesheet"`); got != 1 {
		t.Fatalf("homepage must load exactly one stylesheet, got %d", got)
	}
	for _, forbidden := range []string{
		"koschei.css",
		"koschei-global-shell.css",
		"koschei-universe-v1.css",
		"koschei-home-universe-v2.css",
		"koschei-home-universe-motion-v1.css",
		"koschei-global-shell.js",
		"koschei-product-v2.js",
		`href="/arvis-chat"`,
		`href="/scan`,
		`href="/reports"`,
		`href="/watchlist"`,
		"ETHEREUM</b><small>LIVE",
		"TRON</b><small>LIVE",
		"100% secure",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("homepage regressed into legacy multi-surface or unsupported presentation: found %q", forbidden)
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
