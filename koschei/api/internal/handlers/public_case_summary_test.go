package handlers

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestBuildPublicCaseSummaryExplainsIncompleteGrade(t *testing.T) {
	technical := publicCasePageData{
		CaseRef:        "KD1-g7epiavjdqtk5dsz3s2ynewjkobd2rxz",
		Title:          "ARVIS Actor Evidence Case",
		TargetKind:     "wallet",
		TargetID:       "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe",
		VerdictGrade:   "B",
		RulesetVersion: "koschei-unified-radar-rules-v1.0.0",
		ProducedAt:     time.Date(2026, 7, 25, 5, 3, 0, 0, time.UTC),
		Acceptance: publicCaseAcceptanceView{
			Status:          "fail",
			Class:           "failed",
			Pass:            5,
			Fail:            2,
			NotInvestigated: 3,
		},
		Signals: []publicCaseSignalView{
			{ID: "AC-02", State: "verified", StateClass: "verified"},
			{ID: "AC-04", State: "verified", StateClass: "verified"},
			{ID: "AC-07", State: "unknown", StateClass: "unknown", AcceptanceStatus: "not_investigated"},
			{ID: "AC-10", State: "unknown", StateClass: "unknown", AcceptanceStatus: "fail"},
		},
		Rules: []publicCaseRuleView{
			{ID: "ARD-C003", Count: 1},
			{ID: "ARD-C004", Count: 6},
		},
		TechnicalURL: "/dossier/KD1-g7epiavjdqtk5dsz3s2ynewjkobd2rxz",
	}

	result := buildPublicCaseSummaryPageData(technical)
	if result.OutcomeLabel != "İNCELEME GEREKLİ" {
		t.Fatalf("unexpected outcome label: %q", result.OutcomeLabel)
	}
	if !strings.Contains(result.OutcomeText, "2 kontrol başarısız") || !strings.Contains(result.OutcomeText, "3 alan tamamlanmamış") {
		t.Fatalf("outcome does not explain incomplete acceptance: %q", result.OutcomeText)
	}
	if !strings.Contains(result.GradeExplanation, "güvenli anlamına gelmez") {
		t.Fatalf("grade explanation can be misread as safe: %q", result.GradeExplanation)
	}
	if len(result.Known) != 2 {
		t.Fatalf("expected two plain known findings, got %d", len(result.Known))
	}
	if len(result.Missing) != 2 {
		t.Fatalf("expected two missing findings, got %d", len(result.Missing))
	}
	if !strings.Contains(strings.Join(result.Missing, " "), "Likidite") {
		t.Fatalf("missing liquidity gap was not explained: %#v", result.Missing)
	}
	if !strings.Contains(strings.Join(result.RuleReasons, " "), "6 kez") {
		t.Fatalf("repeated relationship rule was not explained: %#v", result.RuleReasons)
	}
}

func TestPublicCaseSummaryTemplateIsHumanFirst(t *testing.T) {
	data := publicCaseSummaryPageData{
		Case: publicCasePageData{
			CaseRef:        "KD1-g7epiavjdqtk5dsz3s2ynewjkobd2rxz",
			Title:          "ARVIS Actor Evidence Case",
			TargetKind:     "wallet",
			TargetID:       "wallet-address",
			VerdictGrade:   "B",
			RulesetVersion: "rules-v1",
			BundleHash:     "sha256:bundle",
			ProducedAt:     time.Date(2026, 7, 25, 5, 3, 0, 0, time.UTC),
			TechnicalURL:   "/dossier/KD1-g7epiavjdqtk5dsz3s2ynewjkobd2rxz",
			Acceptance:     publicCaseAcceptanceView{Pass: 5, Fail: 2, NotInvestigated: 3},
		},
		OutcomeLabel:     "İNCELEME GEREKLİ",
		OutcomeClass:     "review",
		OutcomeText:      "Kesin sonuç üretilemedi.",
		GradeExplanation: "B güvenli anlamına gelmez.",
		Known:            []string{"Hedef cüzdan olarak doğrulandı."},
		Missing:          []string{"Likidite tamamlanmadı."},
		Actions:          []string{"Yüksek tutarlı işlem yapma."},
		RuleReasons:      []string{"Aynı ilişki tekrarlandı."},
	}
	var out bytes.Buffer
	if err := publicCaseSummaryHTML.Execute(&out, data); err != nil {
		t.Fatalf("render summary: %v", err)
	}
	html := out.String()
	for _, required := range []string{"NE BULDUK?", "NE BULAMADIK?", "NE YAPMALI?", "İNCELEME GEREKLİ", "Ham teknik dossier", "ARVIS evidence coverage", "Evidence timeline"} {
		if !strings.Contains(html, required) {
			t.Fatalf("missing human-first marker %q", required)
		}
	}
	for _, forbidden := range []string{"<pre", "<script", "window."} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("summary regressed to raw/executable presentation: %q", forbidden)
		}
	}
}
