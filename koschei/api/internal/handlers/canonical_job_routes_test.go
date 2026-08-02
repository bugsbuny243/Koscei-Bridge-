package handlers

import "testing"

func TestWeb3JobTypeFromPathExposesCanonicalCustomerRoute(t *testing.T) {
	cases := map[string]string{
		"/api/v1/radar/jobs":     CanonicalInvestigationJobType,
		"/api/jobs/token-scan":   legacyTokenScanJobType,
		"/api/jobs/wallet-score": "wallet_score",
		"/api/jobs/tx-decode":    "tx_decode",
	}
	for path, expected := range cases {
		if got := web3JobTypeFromPath(path); got != expected {
			t.Fatalf("path %s resolved job type %q, want %q", path, got, expected)
		}
	}
	if got := web3JobTypeFromPath("/api/v1/radar/jobs/unknown"); got != "" {
		t.Fatalf("unknown job route resolved as %q", got)
	}
}

func TestCanonicalJobPollPathUsesLastSegment(t *testing.T) {
	cases := map[string]string{
		"/api/owner/radar/jobs/abc-123": "abc-123",
		"/api/v1/radar/jobs/def-456":    "def-456",
		"/api/jobs/ghi-789":             "ghi-789",
		"/api/owner/radar/jobs/":        "",
	}
	for path, expected := range cases {
		if got := lastCanonicalJobPathSegment(path); got != expected {
			t.Fatalf("path %s resolved id %q, want %q", path, got, expected)
		}
	}
}

func TestCanonicalPayloadMaxDepthIsBounded(t *testing.T) {
	if got := canonicalPayloadMaxDepth(canonicalInvestigationJobPayload{MaxDepth: 99}); got != 3 {
		t.Fatalf("recursive max depth escaped hard cap: %d", got)
	}
	if got := canonicalPayloadMaxDepth(canonicalInvestigationJobPayload{MaxDepth: 2}); got != 2 {
		t.Fatalf("explicit recursive depth lost: %d", got)
	}
}
