package handlers

import (
	"strings"
	"testing"
	"time"
)

func TestPublicProgramSnapshotRiskTypes(t *testing.T) {
	tests := []struct {
		name          string
		authorityOpen bool
		executable    bool
		matchStatus   string
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

func TestOnlyRealOnchainChangesArePublic(t *testing.T) {
	got := publicProgramChainChangeTypes([]string{
		"bytecode_changed", "source_match_lost", "upgrade_authority_revoked", "upgrade_authority_changed",
	})
	if strings.Join(got, ",") != "bytecode_changed,upgrade_authority_changed" {
		t.Fatalf("public chain changes=%v", got)
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

func TestPublicProgramRiskVerificationHashUsesPublicPayload(t *testing.T) {
	base := publicProgramRisk{
		Type: "program_control_risk_observed", EventRef: "KDS1-0123456789abcdef0123456789abcdef",
		ProgramID: "Program111", Network: "solana-mainnet", Severity: "high", LifecycleStatus: "current",
		RiskTypes: []string{"upgrade_authority_open"}, Summary: "Program değiştirilebilir.",
		EvidenceRefs: []string{"rpc:getAccountInfo:Program111"}, CurrentSnapshotRef: "KDS1-0123456789abcdef0123456789abcdef",
		CurrentBinaryHash: "sha256:abc", CurrentUpgradeAuthority: "Authority111", CurrentSourceMatch: "not_requested",
		CurrentLoaderKind: "bpf_upgradeable_loader", OccurredAt: time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
	}
	first := finalizePublicProgramRisk(base)
	second := finalizePublicProgramRisk(base)
	if first.VerificationHash == "" || first.VerificationHash != second.VerificationHash {
		t.Fatalf("verification hash is not deterministic: %q %q", first.VerificationHash, second.VerificationHash)
	}
	if first.Decision != "WARN" || first.RecommendedAction == "" {
		t.Fatalf("action contract missing: %#v", first)
	}
	base.CurrentBinaryHash = "sha256:changed"
	changed := finalizePublicProgramRisk(base)
	if changed.VerificationHash == first.VerificationHash {
		t.Fatal("public payload change did not change verification hash")
	}
}

func TestPublicEvidenceRefsExcludePrivateArtifacts(t *testing.T) {
	raw := []byte(`["artifact:KDA1-secret","rpc:getAccountInfo:Program","deployment_snapshot:KDS1-public"]`)
	refs := publicProgramEvidenceRefs(raw)
	if strings.Join(refs, ",") != "deployment_snapshot:KDS1-public,rpc:getAccountInfo:Program" {
		t.Fatalf("public evidence refs=%v", refs)
	}
}

func TestPublicProgramRiskRefsAreImmutableEvidenceRefs(t *testing.T) {
	for _, ref := range []string{"KDCE1-0123456789abcdef0123456789abcdef", "KDS1-0123456789abcdef0123456789abcdef"} {
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
