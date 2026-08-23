package main

import (
	"os"
	"strings"
	"testing"
)

func TestARVISCanonicalProjectionV4Contract(t *testing.T) {
	projection, err := os.ReadFile("public/js/arvis-canonical-projection-v1.js")
	if err != nil {
		t.Fatalf("read canonical projection: %v", err)
	}
	projectionText := string(projection)
	for _, required := range []string{
		"repeat_actor_scan",
		"creator_active_tokens",
		"creator_inactive_or_dead_tokens",
		"actor_lifecycle_status",
		"canonical_creator_verification",
		"evidence_graph",
		"not_applicable",
		"evidenceLabel",
	} {
		if !strings.Contains(projectionText, required) {
			t.Errorf("canonical projection missing %q", required)
		}
	}

	renderer, err := os.ReadFile("public/js/arvis-complete-evidence-v4.js")
	if err != nil {
		t.Fatalf("read evidence v4 renderer: %v", err)
	}
	rendererText := string(renderer)
	for _, required := range []string{
		"CANONICAL PAYLOAD PROJECTION · V4",
		"One payload. One customer-visible truth.",
		"Creator lifecycle",
		"Canonical create slot",
		"RELATIONSHIP GRAPH",
		"NOT BLOCKED · REVIEW REQUIRED",
		"completeEvidenceVersion='4.0.0'",
	} {
		if !strings.Contains(rendererText, required) {
			t.Errorf("evidence v4 renderer missing %q", required)
		}
	}
	if strings.Contains(rendererText, "String(item)") || strings.Contains(rendererText, "[object Object]") {
		t.Fatal("v4 renderer must not stringify evidence objects into object placeholders")
	}
}
