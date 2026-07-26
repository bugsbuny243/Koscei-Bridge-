package handlers

import (
	"strings"
	"testing"
)

func TestPublicProgramSnapshotRiskTypes(t *testing.T) {
	tests := []struct {
		name          string
		authorityOpen bool
		executable    bool
		matchStatus  string
		want          []string
		severity      string
	}{
		{name: "no verified risk", executable: true, matchStatus: "not_requested", want: []string{}, severity: "high"},
		{name: "open authority", authorityOpen: true, executable: true, matchStatus: "not_requested", want: []string{"upgrade_authority_open"}, severity: "high"},
		{name: "verified source mismatch", executable: true, matchStatus: "mismatched", want: []string{"source_binary_mismatch"}, severity: "critical"},
		{name: "not executable", executable: false, matchStatus: "matched_full_binary", want: []string{"program_not_executable"}, severity: "critical"},
		{name: "combined", authorityOpen: true, executable: true, matchStatus: "mismatched", want: []string{"source_binary_mismatch", "upgrade_authority_open"}, severity: "critical"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := publicProgramSnapshotRiskTypes(tt.authorityOpen, tt.executable, tt.matchStatus)
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("risk types=%v want=%v", got, tt.want)
			}
			if len(got) > 0 && publicProgramSnapshotRiskSeverity(got) != tt.severity {
				t.Fatalf("severity=%s want=%s", publicProgramSnapshotRiskSeverity(got), tt.severity)
			}
		})
	}
}

func TestUnverifiedSourceIsNotPublishedAsMismatch(t *testing.T) {
	for _, status := range []string{"not_requested", "invalid_manifest", "not_evaluated", "matched_full_binary", "matched_after_zero_padding_normalization"} {
		got := publicProgramSnapshotRiskTypes(false, true, status)
		if len(got) != 0 {
			t.Fatalf("status %q produced risk types %v", status, got)
		}
	}
}

func TestPublicProgramRiskRefsAreImmutableEvidenceRefs(t *testing.T) {
	valid := []string{
		"KDCE1-0123456789abcdef0123456789abcdef",
		"KDS1-0123456789abcdef0123456789abcdef",
	}
	for _, ref := range valid {
		if !publicProgramRiskRefPattern.MatchString(ref) {
			t.Fatalf("valid ref rejected: %s", ref)
		}
	}
	for _, ref := range []string{"KDCE1-short", "KD1-0123456789abcdef0123456789abcdef", "KDS1-0123456789ABCDEF0123456789ABCDEF"} {
		if publicProgramRiskRefPattern.MatchString(ref) {
			t.Fatalf("invalid ref accepted: %s", ref)
		}
	}
}

func TestPublicProgramRiskLimitationsRejectAttribution(t *testing.T) {
	joined := strings.ToLower(strings.Join(publicProgramRiskLimitations(), " "))
	for _, required := range []string{"niyet", "saldırı", "suç", "verdict"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("publication boundary missing %q: %s", required, joined)
		}
	}
}
