package services

import "testing"

func TestSharedInvestigationOutputPolicyKeepsTechnicalResultEqual(t *testing.T) {
	policy := SharedInvestigationOutputPolicy()
	if policy.Version != InvestigationOutputPolicyVersion {
		t.Fatalf("version=%q", policy.Version)
	}
	if !policy.SameEvidenceEngine || !policy.SameTechnicalResult {
		t.Fatalf("policy=%#v", policy)
	}
	forbidden := map[string]bool{
		"collector_execution":   true,
		"evidence_status":       true,
		"deterministic_verdict": true,
		"ruleset":               true,
		"signature":             true,
	}
	for _, item := range policy.CallerTypeAffects {
		if forbidden[item] {
			t.Fatalf("technical result cannot vary by caller type: %s", item)
		}
	}
	for item := range forbidden {
		found := false
		for _, value := range policy.CallerTypeDoesNotAffect {
			if value == item {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing protected result field %s", item)
		}
	}
}
