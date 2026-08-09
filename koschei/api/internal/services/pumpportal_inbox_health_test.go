package services

import "testing"

func TestClassifyPumpPortalInboxHealth(t *testing.T) {
	cases := []struct {
		name string
		in   PumpPortalInboxHealth
		want string
	}{
		{name: "unavailable", in: PumpPortalInboxHealth{}, want: "unavailable"},
		{name: "healthy", in: PumpPortalInboxHealth{Available: true}, want: "healthy"},
		{name: "recovering retry", in: PumpPortalInboxHealth{Available: true, OpenCount: 1, RetryableCount: 1}, want: "recovering"},
		{name: "recovering age", in: PumpPortalInboxHealth{Available: true, OpenCount: 1, OldestOpenAgeSeconds: 61}, want: "recovering"},
		{name: "backlogged age", in: PumpPortalInboxHealth{Available: true, OpenCount: 1, OldestOpenAgeSeconds: 301}, want: "backlogged"},
		{name: "backlogged count", in: PumpPortalInboxHealth{Available: true, OpenCount: 1000}, want: "backlogged"},
		{name: "degraded exhausted", in: PumpPortalInboxHealth{Available: true, ExhaustedCount: 1}, want: "degraded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyPumpPortalInboxHealth(tc.in); got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}
