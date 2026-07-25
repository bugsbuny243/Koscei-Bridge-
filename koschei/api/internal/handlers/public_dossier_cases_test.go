package handlers

import (
	"testing"
	"time"
)

func TestBuildPublicDossierCaseProjectsOnlyDiscoveryFields(t *testing.T) {
	producedAt := time.Date(2026, 7, 25, 4, 0, 0, 0, time.UTC)
	publishedAt := producedAt.Add(time.Minute)
	bundle := dossierBundle{
		dossierBody: dossierBody{
			DossierVersion: "koschei-dossier-v1",
			CaseRef:        "KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ProducedAt:     producedAt,
			Target: map[string]any{
				"kind": "wallet", "id": "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe", "network": "solana-mainnet",
			},
			Verdict: map[string]any{"grade": "C", "status": "withhold", "ruleset_version": "rules-v1"},
			VerdictCard: map[string]any{"signal_rows": []any{
				map[string]any{"id": "AC-01", "state": "verified"},
				map[string]any{"id": "AC-02", "state": "observed"},
				map[string]any{"id": "AC-03", "state": "inferred"},
				map[string]any{"id": "AC-04", "state": "unknown"},
			}},
			ActorAcceptance: map[string]any{"pass_count": 5.0, "fail_count": 2.0, "not_investigated_count": 3.0},
			CreatedTokenHistory: []any{map[string]any{"mint": "Mint1"}, map[string]any{"mint": "Mint2"}},
			TechnicalReport: map[string]any{"private_internal_field": "must_not_be_projected"},
		},
		BundleHash: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
	}

	item := buildPublicDossierCase(bundle, "Published actor case", "Bounded summary", true, publishedAt, publicDossierRedactionProfile)
	if item.CaseRef != bundle.CaseRef || item.PublicURL != "/dossier/"+bundle.CaseRef {
		t.Fatalf("unexpected identity projection: %#v", item)
	}
	if item.TargetKind != "wallet" || item.TargetDisplay != "yHCxHBE…Hcx6PRe" {
		t.Fatalf("unexpected target projection: kind=%q display=%q", item.TargetKind, item.TargetDisplay)
	}
	if item.EvidenceRows != 4 || item.VerifiedRows != 1 || item.ObservedRows != 1 || item.InferredRows != 1 || item.UnknownRows != 1 {
		t.Fatalf("unexpected evidence counts: %#v", item)
	}
	if item.AcceptancePass != 5 || item.AcceptanceFail != 2 || item.AcceptanceNotInvestigated != 3 {
		t.Fatalf("unexpected acceptance counts: %#v", item)
	}
	if item.CreatedTokenHistoryCount != 2 || item.BundleHash == "" || item.IndependentVerificationPath == "" {
		t.Fatalf("missing public proof fields: %#v", item)
	}
}

func TestPublicDossierPublicationAction(t *testing.T) {
	tests := []struct {
		name             string
		exists           bool
		previousStatus   string
		previousFeatured bool
		nextStatus       string
		nextFeatured     bool
		want             string
	}{
		{name: "first publish", nextStatus: "public", want: "publish"},
		{name: "first draft", nextStatus: "draft", want: "draft"},
		{name: "hide", exists: true, previousStatus: "public", nextStatus: "hidden", want: "hide"},
		{name: "republish", exists: true, previousStatus: "hidden", nextStatus: "public", want: "publish"},
		{name: "feature", exists: true, previousStatus: "public", nextStatus: "public", nextFeatured: true, want: "feature"},
		{name: "unfeature", exists: true, previousStatus: "public", previousFeatured: true, nextStatus: "public", want: "unfeature"},
		{name: "metadata update", exists: true, previousStatus: "public", nextStatus: "public", want: "update"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := publicDossierPublicationAction(tt.exists, tt.previousStatus, tt.previousFeatured, tt.nextStatus, tt.nextFeatured)
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestPublicDossierBoundaries(t *testing.T) {
	if got := publicDossierLimit("999", 24, 100); got != 100 {
		t.Fatalf("limit=%d", got)
	}
	if got := publicDossierLimit("bad", 24, 100); got != 24 {
		t.Fatalf("fallback=%d", got)
	}
	if got := maskPublicDossierTarget("short"); got != "short" {
		t.Fatalf("short target=%q", got)
	}
	if got := boundedPublicDossierText("  abc  ", 10); got != "abc" {
		t.Fatalf("bounded text=%q", got)
	}
}
