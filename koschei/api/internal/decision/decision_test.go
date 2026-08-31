package decision

import "testing"

func TestFromTransactionGuard(t *testing.T) {
	tests := []struct {
		in     string
		want   Action
		reason string
	}{
		{"allow", ActionAllow, ""},
		{"warn", ActionWarn, ""},
		{"block", ActionBlock, ""},
		{"withhold", ActionWithhold, "rpc_unavailable"},
		{"mystery", ActionWithhold, "rpc_unavailable"},
	}
	for _, tc := range tests {
		got := FromTransactionGuard(tc.in, "rpc_unavailable")
		if got.Action != tc.want {
			t.Fatalf("%s: action=%s want=%s", tc.in, got.Action, tc.want)
		}
		if got.WithholdReason != tc.reason {
			t.Fatalf("%s: reason=%q want=%q", tc.in, got.WithholdReason, tc.reason)
		}
	}
}

func TestFromUnifiedRadar(t *testing.T) {
	tests := []struct {
		grade   string
		verdict string
		want    Action
		reason  string
	}{
		{"A", "hard_trigger", ActionAllow, ""},
		{"B", "compounding_rule", ActionAllow, ""},
		{"C", "hard_trigger", ActionWarn, ""},
		{"D", "hard_trigger", ActionBlock, ""},
		{"E", "hard_trigger", ActionBlock, ""},
		{"F", "hard_trigger", ActionBlock, ""},
		{"-", "single_observation", ActionWithhold, "single_evidence_rule_only"},
		{"-", "watch_only", ActionWithhold, "watch_only_evidence"},
		{"-", "evidence_only", ActionWithhold, "evidence_only_mode"},
		{"-", "no_grade_trigger", ActionWithhold, "no_grade_changing_evidence"},
	}
	for _, tc := range tests {
		got := FromUnifiedRadar(tc.grade, tc.verdict)
		if got.Action != tc.want || got.WithholdReason != tc.reason {
			t.Fatalf("grade=%s verdict=%s: got=%+v", tc.grade, tc.verdict, got)
		}
	}
}

func TestFromExecutionContainment(t *testing.T) {
	tests := []struct {
		legacy string
		want   Action
		reason string
	}{
		{"RELEASE", ActionAllow, ""},
		{"CONTAIN", ActionBlock, ""},
		{"UNAVAILABLE", ActionWithhold, "execution_backend_unavailable"},
		{"", ActionWithhold, "unknown_execution_containment_decision"},
	}
	for _, tc := range tests {
		got := FromExecutionContainment(tc.legacy)
		if got.Action != tc.want || got.WithholdReason != tc.reason {
			t.Fatalf("legacy=%s: got=%+v", tc.legacy, got)
		}
	}
}
