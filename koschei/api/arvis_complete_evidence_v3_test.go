package main

import (
	"os"
	"strings"
	"testing"
)

func TestARVISCompleteEvidenceV3IsCompatibilityOnly(t *testing.T) {
	body, err := os.ReadFile("public/js/arvis-complete-evidence-v3.js")
	if err != nil {
		t.Fatalf("read v3 compatibility asset: %v", err)
	}
	text := string(body)
	for _, required := range []string{
		"completeEvidenceVersion='3.0.0'",
		"deprecated_projection_removed",
		"rendering_authority:false",
		"arvis-complete-evidence-v4.js",
		"arvis-canonical-projection-v1.js",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("v3 compatibility asset missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"function extract(payload)",
		"Creator wallet',text(first",
		"No relationship edge was attached to the canonical payload.",
		"[object Object]",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("deprecated v3 still contains independent projection behavior %q", forbidden)
		}
	}
}
