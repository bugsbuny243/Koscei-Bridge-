package http

import (
	"testing"
	"time"
)

func TestSensitiveRuleCoversPublicTransactionSimulator(t *testing.T) {
	rule, ok := sensitiveRuleForPath("/api/public/transaction-simulate")
	if !ok {
		t.Fatal("public transaction simulator is not protected by the shared rate limiter")
	}
	if rule.Limit != 10 || rule.Window != time.Minute {
		t.Fatalf("public transaction simulator rate limit = %+v, want 10 per minute", rule)
	}
}
