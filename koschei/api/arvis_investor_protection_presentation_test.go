package main

import (
	"os"
	"strings"
	"testing"
)

func TestInvestorProtectionAssetsInjectedIntoPremiumPages(t *testing.T) {
	body := rewritePublicHTMLToEnglish([]byte(`<!doctype html><html><body><script src="/js/arvis-premium-contract.js"></script></body></html>`))
	text := string(body)
	for _, marker := range []string{
		"arvis-investor-protection-v1.js?v=1",
		"koschei.css?v=1",
		"arvis-complete-evidence-v4.js?v=4",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("premium page missing investor protection asset %q: %s", marker, text)
		}
	}
}

func TestSharedInvestorProtectionConsumesBackendDecisionAndVerdictReferences(t *testing.T) {
	content, err := os.ReadFile("public/js/arvis-investor-protection-v1.js")
	if err != nil {
		t.Fatalf("read shared investor protection asset: %v", err)
	}
	text := string(content)
	for _, marker := range []string{
		"investor_protection_decision",
		"AVOID · BLOCK",
		"NOT CLEARED · WITHHOLD",
		"triggered_rules",
		"evidence_keys",
		"transaction_signature",
		"References are not silently promoted into standalone canonical rows.",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("shared investor protection asset missing %q", marker)
		}
	}
}
