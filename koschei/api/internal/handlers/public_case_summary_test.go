package handlers

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestPublicCaseSummaryWithholdsInvalidLetterGrade(t *testing.T) {
	technical := publicCasePageData{
		CaseRef: "KD1-g7epiavjdqtk5dsz3s2ynewjkobd2rxz", Title: "ARVIS Actor Evidence Case",
		TargetKind: "wallet", TargetID: "wallet-address", VerdictGrade: "B", VerdictStatus: "review",
		RulesetVersion: "rules-v1", ProducedAt: time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
		Signals: []publicCaseSignalView{
			{ID: "AC-02", State: "verified", StateClass: "verified", AcceptanceStatus: "pass"},
			{ID: "AC-10", State: "unknown", StateClass: "unknown", AcceptanceStatus: "fail"},
		},
		Rules: []publicCaseRuleView{{ID: "ARD-C004", Count: 2}, {ID: "ARD-C004", Count: 3}},
	}
	result := buildPublicCaseSummaryPageData(technical)
	if result.GradeDisplay != "WITHHOLD" || result.DecisionLabel != "İŞLEMİ BEKLET" {
		t.Fatalf("invalid grade was not withheld: %#v", result)
	}
	if len(result.Reasons) != 1 || !strings.Contains(result.Reasons[0], "5 doğrulanmış işlem") {
		t.Fatalf("repeated rules were not collapsed: %#v", result.Reasons)
	}
	if len(result.Findings) != 1 || !strings.Contains(result.Findings[0], "hesap türü") {
		t.Fatalf("verified finding missing: %#v", result.Findings)
	}
}

func TestPublicCaseSummaryDecisionMapping(t *testing.T) {
	tests := []struct {
		grade, status, want string
	}{
		{"F", "block", "BLOKLA"},
		{"B", "warn", "YÜKSEK DİKKAT"},
		{"A", "allow", "KANITLA DEVAM"},
		{"-", "withhold", "İŞLEMİ BEKLET"},
	}
	for _, tt := range tests {
		data := publicCasePageData{VerdictGrade: tt.grade, VerdictStatus: tt.status}
		grade := publicCaseEffectiveGrade(data)
		got, _, _ := publicCaseDecision(data, grade)
		if got != tt.want {
			t.Fatalf("grade=%s status=%s decision=%s want=%s", tt.grade, tt.status, got, tt.want)
		}
	}
}

func TestPublicCaseSummaryTemplateShowsProductNotWorkerDebug(t *testing.T) {
	data := publicCaseSummaryPageData{
		Case: publicCasePageData{
			CaseRef: "KD1-g7epiavjdqtk5dsz3s2ynewjkobd2rxz", Title: "ARVIS Security Case",
			TargetKind: "wallet", TargetID: "wallet-address", BundleHash: "sha256:bundle",
			RulesetVersion: "rules-v1", Signature: "signature", Network: "solana-mainnet",
			ProducedAt: time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC), TechnicalURL: "/dossier/KD1-g7epiavjdqtk5dsz3s2ynewjkobd2rxz",
		},
		TargetLabel: "Cüzdan", DecisionLabel: "İŞLEMİ BEKLET", DecisionClass: "withhold",
		DecisionText: "İşlemi imzalama.", GradeDisplay: "WITHHOLD", GradeExplanation: "Kanıt sınırı.",
		Findings: []string{"Doğrulanmış zincir üstü bulgu."}, Reasons: []string{"Aynı ilişki 5 işlemde tekrarlandı."},
		Actions: []string{"İşlemi şimdilik imzalama."},
	}
	var out bytes.Buffer
	if err := publicCaseSummaryHTML.Execute(&out, data); err != nil {
		t.Fatalf("render summary: %v", err)
	}
	html := out.String()
	for _, required := range []string{"ARVIS KARARI", "NE BULDUK?", "NEDEN ÖNEMLİ?", "NE YAPMALISIN?", "Değişmez kanıt dosyasını aç", "WITHHOLD"} {
		if !strings.Contains(html, required) {
			t.Fatalf("missing product marker %q", required)
		}
	}
	for _, forbidden := range []string{"Sorumlu worker", "ARVIS ŞİMDİ NE YAPACAK?", "Açık otomatik işler", "<pre", "<script", "window."} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("public page leaked operational/debug marker %q", forbidden)
		}
	}
}
