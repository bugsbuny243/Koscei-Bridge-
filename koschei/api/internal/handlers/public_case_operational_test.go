package handlers

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestBuildPublicCaseOperationalAssignsOpenChecksToARVIS(t *testing.T) {
	technical := publicCasePageData{
		CaseRef:        "KD1-operationalcase000000000000000",
		Title:          "ARVIS Actor Evidence Case",
		TargetKind:     "wallet",
		TargetID:       "wallet-address",
		VerdictGrade:   "B",
		RulesetVersion: "rules-v1",
		ProducedAt:     time.Date(2026, 7, 25, 19, 0, 0, 0, time.UTC),
		Acceptance: publicCaseAcceptanceView{
			Status: "fail", Pass: 4, Fail: 3, NotInvestigated: 3,
		},
		Signals: []publicCaseSignalView{
			{ID: "AC-01", AcceptanceStatus: "pass", StateClass: "verified"},
			{ID: "AC-04", AcceptanceStatus: "fail", StateClass: "failed"},
			{ID: "AC-05", AcceptanceStatus: "not_investigated", StateClass: "unknown"},
			{ID: "AC-06", AcceptanceStatus: "not_investigated", StateClass: "unknown"},
			{ID: "AC-07", AcceptanceStatus: "not_investigated", StateClass: "unknown"},
			{ID: "AC-08", AcceptanceStatus: "fail", StateClass: "failed"},
			{ID: "AC-10", AcceptanceStatus: "fail", StateClass: "failed"},
		},
		TechnicalURL: "/dossier/KD1-operationalcase000000000000000",
	}

	result := buildPublicCaseOperationalPageData(technical)
	if result.OutcomeLabel != "SONUÇ BEKLETİLİYOR" {
		t.Fatalf("unexpected outcome: %q", result.OutcomeLabel)
	}
	if !strings.Contains(result.OutcomeText, "Koschei worker görevleridir") {
		t.Fatalf("manual ownership was not rejected: %q", result.OutcomeText)
	}
	if len(result.Jobs) != 6 {
		t.Fatalf("expected six open system jobs, got %d", len(result.Jobs))
	}
	joined := ""
	for _, job := range result.Jobs {
		joined += job.Worker + " " + job.AutomaticAction + " " + job.UserRequirement + "\n"
	}
	for _, required := range []string{"ARVIS Funding Origin Worker", "ARVIS Distribution Worker", "ARVIS Holder Intelligence Worker", "ARVIS Liquidity Intelligence Worker", "ARVIS Cross-Token Correlator", "ARVIS Deterministic Verdict Engine", "manuel zincir analizi beklenmez"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing operational ownership %q in %s", required, joined)
		}
	}
}

func TestPublicCaseOperationalTemplateExplainsWhoDoesWhat(t *testing.T) {
	data := publicCaseOperationalPageData{
		Case: publicCasePageData{
			CaseRef: "KD1-operationalcase000000000000000", Title: "ARVIS Case",
			TargetKind: "wallet", TargetID: "wallet-address", TechnicalURL: "/dossier/ref",
			Acceptance: publicCaseAcceptanceView{Pass: 4, Fail: 3, NotInvestigated: 3},
			BundleHash: "sha256:bundle", RulesetVersion: "rules-v1",
			ProducedAt: time.Date(2026, 7, 25, 19, 0, 0, 0, time.UTC),
		},
		OutcomeLabel: "SONUÇ BEKLETİLİYOR", OutcomeClass: "review",
		OutcomeText: "Açık işler Koschei worker görevleridir.", GradeDisplay: "WITHHOLD",
		GradeExplanation: "Açık otomatik işler varken işlem onayı verilmez.",
		Completed:        []string{"Cüzdan hedefi doğrulandı."},
		Jobs: []publicCaseOperationalJob{{
			ID: "AC-07", Title: "Likidite izini tamamla", State: "OTOMATİK İŞ AÇIK", Class: "queued",
			Worker: "ARVIS Liquidity Intelligence Worker", AutomaticAction: "DEX/pool add/remove imzalarını tarayacak.",
			Reason: "Pool kanıtı eksik.", UserRequirement: "Yok. Bu Koschei worker görevidir.",
		}},
		RuleReasons: []string{"Kanıt destekli kural yok."},
	}
	var out bytes.Buffer
	if err := publicCaseOperationalHTML.Execute(&out, data); err != nil {
		t.Fatalf("render operational case: %v", err)
	}
	html := out.String()
	for _, required := range []string{"ARVIS ŞİMDİ NE YAPACAK?", "Açık otomatik işler", "Sorumlu worker", "Otomatik işlem", "Neden açık?", "Kullanıcıdan gereken", "ARVIS Liquidity Intelligence Worker", "SONUÇ BEKLETİLİYOR", "WITHHOLD", "Ham teknik dossier"} {
		if !strings.Contains(html, required) {
			t.Fatalf("missing operational marker %q", required)
		}
	}
	for _, forbidden := range []string{"NE YAPMALI?", "<pre", "<script", "window."} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("operational page contains forbidden marker %q", forbidden)
		}
	}
}
