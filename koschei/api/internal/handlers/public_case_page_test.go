package handlers

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestBuildPublicCasePageDataCreatesReadableEvidenceView(t *testing.T) {
	produced := time.Date(2026, 7, 25, 5, 0, 0, 0, time.UTC)
	bundle := dossierBundle{
		dossierBody: dossierBody{
			DossierVersion: "koschei-dossier-v1",
			CaseRef:        "KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ProducedAt:     produced,
			Target: map[string]any{
				"kind": "wallet", "id": "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe", "network": "solana-mainnet",
			},
			Verdict: map[string]any{
				"grade": "B", "verdict": "compounding_rule", "ruleset_version": "rules-v1", "signature": "sig-v1",
				"decision_path": []any{"No weighted score is calculated.", "Two evidence-backed rules lowered the baseline."},
				"triggered_rules": []any{map[string]any{
					"rule_id": "ARD-C004", "title": "Repeated direct transfer relation", "evidence_status": "verified", "summary": "Observed six times.", "count": 6.0,
				}},
			},
			VerdictCard: map[string]any{"signal_rows": []any{
				map[string]any{"id": "AC-01", "label": "Wallet classified", "state": "verified", "acceptance_status": "pass", "value": map[string]any{"summary": "Wallet target was resolved."}, "refs": map[string]any{"wallets": []any{"wallet"}}},
				map[string]any{"id": "AC-02", "label": "Actor recurrence", "state": "observed", "acceptance_status": "pass", "value": map[string]any{"summary": "One related actor observed."}},
			}},
			ActorAcceptance:       map[string]any{"status": "pass", "pass_count": 8.0, "fail_count": 0.0, "not_investigated_count": 2.0, "acceptance_hash": "sha256:acceptance"},
			FundingOrigin:         map[string]any{"verification_status": "verified", "source_wallet": "SourceWallet", "destination_wallet": "DestinationWallet", "amount_sol": 1.25, "observed_at": produced.Add(-time.Hour).Format(time.RFC3339), "signature": "FundingSignature", "slot": 42.0, "program": "system"},
			CreatedTokenHistory:   []any{map[string]any{"mint": "9cRCn9rGT8V2imeM2BaKs13yhMEais3ruM3rPvTGpump", "verification_status": "observed", "roles": []any{"creator_deployer"}, "first_observed_at": produced.Add(-48 * time.Hour).Format(time.RFC3339)}},
			CrossTokenConnections: map[string]any{"counts": map[string]any{"created_tokens": 1.0, "related_actors": 1.0}, "related_actor_observations": []any{map[string]any{"wallet": "GV6UUmNxz2RpKxmNAPadYKb7uQpszwqQAu3qLJxVdC52", "verification_status": "observed", "shared_token_count": 1.0, "max_holder_percentage": 58.7}}},
			EvidenceLog: []any{
				map[string]any{"relation": "direct_sol_transfer_in", "verification_status": "verified", "source_wallet": "A", "destination_wallet": "B", "observed_at": produced.Add(-time.Hour).Format(time.RFC3339), "signature": "OlderSignature", "slot": 1.0, "amount": map[string]any{"native_sol": 0.25}},
				map[string]any{"relation": "created_token", "verification_status": "observed", "source_wallet": "A", "destination_wallet": "Mint", "observed_at": produced.Format(time.RFC3339), "signature": "NewerSignature", "slot": 2.0},
			},
			Limitations: []string{"No real-world identity attribution."},
		},
		BundleHash: "sha256:bundle",
	}

	data := buildPublicCasePageData(bundle, "Published actor case", "Readable evidence summary", true, produced.Add(time.Minute))
	if data.VerdictGrade != "B" || data.VerdictText != "Compounding Rule" {
		t.Fatalf("unexpected verdict projection: %#v", data)
	}
	if len(data.Signals) != 2 || data.Signals[0].ReferenceCount != 1 {
		t.Fatalf("unexpected signal projection: %#v", data.Signals)
	}
	if len(data.Rules) != 1 || data.Rules[0].ID != "ARD-C004" {
		t.Fatalf("unexpected rules: %#v", data.Rules)
	}
	if !data.Funding.Available || data.Funding.Amount != "1.25 SOL" {
		t.Fatalf("unexpected funding view: %#v", data.Funding)
	}
	if len(data.Evidence) != 2 || data.Evidence[0].Signature != "NewerSignature" {
		t.Fatalf("evidence was not sorted newest-first: %#v", data.Evidence)
	}
	if data.TechnicalURL != "/dossier/"+bundle.CaseRef {
		t.Fatalf("technical URL = %q", data.TechnicalURL)
	}
}

func TestPublicCaseTemplateIsHumanReadableAndKeepsRawDossierSeparate(t *testing.T) {
	data := publicCasePageData{
		CaseRef: "KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Title: "Actor Evidence Case", Summary: "Evidence summary",
		BundleHash: "sha256:bundle", TargetKind: "wallet", TargetID: "wallet", TargetDisplay: "wallet", Network: "solana-mainnet",
		VerdictGrade: "B", VerdictStatus: "compounding_rule", VerdictText: "Compounding Rule", RulesetVersion: "rules-v1",
		Acceptance:   publicCaseAcceptanceView{Status: "pass", Class: "verified", Pass: 8, NotInvestigated: 2},
		TechnicalURL: "/dossier/KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	var output bytes.Buffer
	if err := publicCaseHTML.Execute(&output, data); err != nil {
		t.Fatalf("template execute: %v", err)
	}
	html := output.String()
	for _, required := range []string{"ARVIS evidence coverage", "Bu vaka ne söylüyor?", "Ham teknik dossier", data.TechnicalURL} {
		if !strings.Contains(html, required) {
			t.Fatalf("rendered casefile missing %q", required)
		}
	}
	if strings.Contains(html, `<pre>`) || strings.Contains(html, `window.`) || strings.Contains(html, `<script`) {
		t.Fatalf("public casefile regressed into raw or executable output")
	}
}

func TestPublicCaseStateClasses(t *testing.T) {
	for input, want := range map[string]string{"verified": "verified", "observed": "observed", "inferred": "inferred", "fail": "failed", "": "unknown"} {
		if got := publicCaseStateClass(input); got != want {
			t.Fatalf("state %q = %q want %q", input, got, want)
		}
	}
}
