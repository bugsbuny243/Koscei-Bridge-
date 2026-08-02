package handlers

import (
	"strings"
	"testing"
)

func TestPublicCaseFundingRendersBoundedByChain(t *testing.T) {
	view := publicCaseFunding(map[string]any{
		"result_state":        "bounded",
		"verification_status": "unverified",
		"boundary": map[string]any{
			"kind":                "configured_signature_window",
			"reason":              "configured boundary reached",
			"pages_scanned":       8,
			"signatures_walked":   2000,
			"transactions_parsed": 60,
			"oldest_slot":         12345,
			"raisable":            true,
		},
	})
	if view.State != "bounded" || view.Status != "zincir sınırı" || view.ClaimAvailable {
		t.Fatalf("view=%+v", view)
	}
	if !strings.Contains(view.Boundary, "2000 imza") || !strings.Contains(view.Raisable, "yükseltilebilir") {
		t.Fatalf("boundary=%q raisable=%q", view.Boundary, view.Raisable)
	}
	if strings.Contains(strings.ToLower(view.Summary), "başarısız") || strings.Contains(strings.ToLower(view.Summary), "eksik") {
		t.Fatalf("bounded copy misrepresents collector result: %q", view.Summary)
	}
}

func TestPublicCaseFundingRendersHardCeilingAsNotRaisable(t *testing.T) {
	view := publicCaseFunding(map[string]any{
		"result_state": "bounded",
		"boundary": map[string]any{
			"kind":                      "hard_signature_ceiling",
			"pages_scanned":             20,
			"signatures_walked":         20000,
			"transactions_parsed":       250,
			"effective_signature_limit": 20000,
			"reached_hard_ceiling":      true,
			"raisable":                  false,
		},
	})
	if !strings.Contains(view.Boundary, "20000 imza") || !strings.Contains(view.Raisable, "yapılandırmayla daha derine inilemez") {
		t.Fatalf("view=%+v", view)
	}
}

func TestPublicCaseFundingRendersMissingAsWorkerDebt(t *testing.T) {
	view := publicCaseFunding(nil)
	if view.State != "missing" || view.Status != "worker borcu" || view.ClaimAvailable {
		t.Fatalf("view=%+v", view)
	}
	if !strings.Contains(strings.ToLower(view.Summary), "henüz") {
		t.Fatalf("missing copy=%q", view.Summary)
	}
}

func TestPublicCaseFundingRendersVerifiedClaimOnlyWithCanonicalFields(t *testing.T) {
	view := publicCaseFunding(map[string]any{
		"result_state":        "verified",
		"verification_status": "verified",
		"source_wallet":       "source-wallet",
		"destination_wallet":  "destination-wallet",
		"signature":           "funding-signature",
		"slot":                99,
		"amount_sol":          1.25,
		"program":             "system",
	})
	if view.State != "verified" || !view.ClaimAvailable || view.Source != "source-wallet" || view.Signature != "funding-signature" {
		t.Fatalf("view=%+v", view)
	}
}
