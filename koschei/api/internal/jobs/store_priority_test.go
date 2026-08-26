package jobs

import (
	"strings"
	"testing"
)

func TestClaimNextPriorityOrderContract(t *testing.T) {
	checks := []string{
		"customer_canonical_job' THEN 0",
		"owner_manual_canonical_job' THEN 10",
		"background_recursive_token_scan' THEN 30",
		"LIKE 'background_%' THEN 40",
		"ELSE 20",
		"queued_at ASC, id ASC",
	}
	for _, want := range checks {
		if !strings.Contains(claimNextPriorityOrder, want) {
			t.Fatalf("claim priority order missing %q: %s", want, claimNextPriorityOrder)
		}
	}
}
