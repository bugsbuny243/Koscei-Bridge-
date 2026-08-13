package handlers

import "testing"

func TestOwnerActionQueueRoutesCriticalWork(t *testing.T) {
	summary := map[string]any{
		"security_feedback":            int64(2),
		"critical_security_events_24h": int64(3),
		"open_feedback":                int64(5),
		"expiring_entitlements_7d":     int64(6),
		"failed_jobs_24h":              int64(7),
	}
	arvis := map[string]any{"processing_failed_recent": int64(8)}
	services := map[string]any{
		"database": map[string]any{"status": "connected"},
		"paddle":   map[string]any{"status": "not_configured"},
	}

	actions := ownerActionQueue(summary, services, arvis)
	assertOwnerAction(t, actions, "arvis_failure", "critical", "arvis", 8)
	assertOwnerAction(t, actions, "security_feedback", "critical", "feedback", 2)
	assertOwnerAction(t, actions, "security_events", "high", "security", 3)
	assertOwnerAction(t, actions, "expiring_entitlement", "medium", "customers", 6)
	assertOwnerAction(t, actions, "failed_jobs", "medium", "system", 7)
	assertOwnerAction(t, actions, "service", "medium", "system", 1)
}

func TestOwnerActionQueueOmitsHealthyAndZeroItems(t *testing.T) {
	actions := ownerActionQueue(
		map[string]any{},
		map[string]any{
			"database": map[string]string{"status": "connected"},
			"paddle":   map[string]any{"status": "configured"},
		},
		map[string]any{},
	)
	if len(actions) != 0 {
		t.Fatalf("expected no owner actions for healthy zero state, got %#v", actions)
	}
}

func TestOwnerServiceStatusShapes(t *testing.T) {
	cases := []struct {
		name string
		raw  any
		want string
	}{
		{name: "string", raw: "configured", want: "configured"},
		{name: "any map", raw: map[string]any{"status": "not_configured"}, want: "not_configured"},
		{name: "string map", raw: map[string]string{"status": "connected"}, want: "connected"},
		{name: "unknown", raw: 42, want: "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ownerServiceStatus(tc.raw); got != tc.want {
				t.Fatalf("ownerServiceStatus(%#v)=%q want=%q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestOwnerServiceNeedsAction(t *testing.T) {
	for _, status := range []string{"missing", "unavailable", "error", "not_configured", "partial", "unknown", "degraded", "stale"} {
		if !ownerServiceNeedsAction(status) {
			t.Fatalf("status %q should require owner action", status)
		}
	}
	for _, status := range []string{"configured", "connected", "healthy", "active", "manual"} {
		if ownerServiceNeedsAction(status) {
			t.Fatalf("status %q should not require owner action", status)
		}
	}
}

func assertOwnerAction(t *testing.T, actions []map[string]any, kind, priority, tab string, count int64) {
	t.Helper()
	for _, action := range actions {
		if action["kind"] != kind {
			continue
		}
		if action["priority"] != priority || action["target_tab"] != tab || mapInt64(action, "count") != count {
			t.Fatalf("unexpected action for %s: %#v", kind, action)
		}
		return
	}
	t.Fatalf("missing owner action kind=%s in %#v", kind, actions)
}
