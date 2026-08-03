package main

import (
	"os"
	"strings"
	"testing"
)

func TestARVISCompleteEvidenceV3Contract(t *testing.T) {
	body, err := os.ReadFile("public/js/arvis-complete-evidence-v3.js")
	if err != nil {
		t.Fatalf("read complete evidence renderer: %v", err)
	}
	text := string(body)
	for _, required := range []string{
		"COMPLETE CANONICAL SCAN COVERAGE",
		"Top 1",
		"Top 3",
		"Top 10",
		"Top 20",
		"AUTHORITY & TRANSFER CONTROLS",
		"ALL ARVIS MODULES",
		"OWNER-RESOLVED HOLDER SURFACE",
		"CREATOR, FUNDING & LAUNCH",
		"RELATIONSHIP GRAPH",
		"EVIDENCE COVERAGE",
		"LIMITS & UNKNOWN BRANCHES",
		"Download canonical JSON",
		"completeEvidenceVersion='3.0.0'",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("complete evidence renderer missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"No strong coordination means safe",
		"Missing data is safe",
		"same real-world owner",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("complete evidence renderer contains unsafe claim %q", forbidden)
		}
	}
}
