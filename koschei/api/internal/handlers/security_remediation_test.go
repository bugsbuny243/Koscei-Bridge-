package handlers

import "testing"

func TestAPIKeyHashIsPepperedAndDeterministic(t *testing.T) {
	t.Setenv("API_KEY_PEPPER", "pepper-one")
	first := hashAPIKey("kch_live_test-key")
	second := hashAPIKey("kch_live_test-key")
	if first == "" || first != second {
		t.Fatalf("API key hash is not stable: first=%q second=%q", first, second)
	}
	t.Setenv("API_KEY_PEPPER", "pepper-two")
	if changed := hashAPIKey("kch_live_test-key"); changed == first {
		t.Fatal("API key pepper did not affect the HMAC")
	}
}

func TestConstantTimeStringEqualChecksValueAndLength(t *testing.T) {
	if !constantTimeStringEqual("owner-secret", "owner-secret") {
		t.Fatal("equal secrets did not compare equal")
	}
	if constantTimeStringEqual("owner-secret", "owner-secret-extra") || constantTimeStringEqual("owner-secret", "wrong-secret") {
		t.Fatal("different secrets compared equal")
	}
}

func TestFundingAssistantMilestonesAreBounded(t *testing.T) {
	draft := fundingAssistantDraft(fundingAssistantInput{ProjectName: "Koschei", MilestoneCount: 1_000_000})
	milestones, ok := draft["milestones"].([]map[string]string)
	if !ok || len(milestones) != 12 {
		t.Fatalf("bounded milestones=%T len=%d, want 12", draft["milestones"], len(milestones))
	}
}
