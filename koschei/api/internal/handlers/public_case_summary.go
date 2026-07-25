package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

type publicCaseSummaryPageData struct {
	Case             publicCasePageData
	OutcomeLabel     string
	OutcomeClass     string
	OutcomeText      string
	GradeExplanation string
	Known            []string
	Missing          []string
	Actions          []string
	RuleReasons      []string
	Evidence         []publicCaseSummaryEvidence
}

type publicCaseSummaryEvidence struct {
	State       string
	Class       string
	Relation    string
	ObservedAt  string
	Amount      string
	Source      string
	Destination string
	Program     string
	Slot        string
	Signature   string
}

// PublicCaseSummaryPage is the customer-facing case surface. It deliberately
// explains the immutable dossier in plain Turkish before exposing technical
// detail. The canonical bundle, verdict and evidence rows are never mutated.
func (h *Handler) PublicCaseSummaryPage(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.DB == nil {
		http.NotFound(w, r)
		return
	}
	caseRef := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/case/"))
	if !publicDossierCaseRefPattern.MatchString(caseRef) {
		http.NotFound(w, r)
		return
	}

	var canonical []byte
	var title, summary string
	var featured bool
	var publishedAt time.Time
	err := h.DB.QueryRowContext(r.Context(), `
		SELECT e.canonical_bundle,p.public_title,p.public_summary,p.featured,p.published_at
		FROM dossier_exports e
		JOIN dossier_publications p ON p.case_ref=e.case_ref
		WHERE e.case_ref=$1 AND p.status='public'`, caseRef).
		Scan(&canonical, &title, &summary, &featured, &publishedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "public case unavailable", http.StatusServiceUnavailable)
		return
	}

	var bundle dossierBundle
	if json.Unmarshal(canonical, &bundle) != nil || bundle.CaseRef != caseRef || bundle.BundleHash == "" {
		http.Error(w, "public case integrity check failed", http.StatusConflict)
		return
	}

	technical := buildPublicCasePageData(bundle, title, summary, featured, publishedAt)
	data := buildPublicCaseSummaryPageData(technical)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60, stale-while-revalidate=300")
	w.Header().Set("X-Robots-Tag", "index, follow")
	if err := publicCaseSummaryHTML.Execute(w, data); err != nil {
		http.Error(w, "public case summary render failed", http.StatusInternalServerError)
	}
}

func buildPublicCaseSummaryPageData(data publicCasePageData) publicCaseSummaryPageData {
	known := make([]string, 0, len(data.Signals))
	missing := make([]string, 0, len(data.Signals))
	for _, signal := range data.Signals {
		if signal.StateClass == "verified" || signal.StateClass == "observed" {
			known = append(known, publicCaseKnownText(signal))
			continue
		}
		missing = append(missing, publicCaseMissingText(signal))
	}
	known = compactPublicCaseStrings(known, 5)
	missing = compactPublicCaseStrings(missing, 5)

	outcomeLabel := "İNCELEME GEREKLİ"
	outcomeClass := "review"
	outcomeText := fmt.Sprintf(
		"Bu dosyada %s harf notu üretildi; ancak kabul testinde %d kontrol başarısız ve %d alan tamamlanmamış durumda. Bu nedenle sonuç güvenli veya tehlikeli diye kesinleştirilemez.",
		data.VerdictGrade, data.Acceptance.Fail, data.Acceptance.NotInvestigated,
	)
	if data.Acceptance.Fail == 0 && data.Acceptance.NotInvestigated == 0 {
		outcomeLabel = "KANIT KAPSAMI TAMAM"
		outcomeClass = "complete"
		outcomeText = fmt.Sprintf("Bu dosyada %s harf notu üretildi ve kabul kontrolleri tamamlandı. Yine de sonuç yalnız zincir üstü teknik kanıta dayanır; gerçek kişi veya niyet iddiası değildir.", data.VerdictGrade)
	}

	ruleReasons := make([]string, 0, len(data.Rules))
	for _, rule := range data.Rules {
		ruleReasons = append(ruleReasons, publicCaseRuleReason(rule))
	}
	if len(ruleReasons) == 0 {
		ruleReasons = append(ruleReasons, "Harf notunu etkileyen deterministik kural bu bundle içinde açıklanmadı.")
	}

	evidence := make([]publicCaseSummaryEvidence, 0, 8)
	for index, row := range data.Evidence {
		if index >= 8 {
			break
		}
		evidence = append(evidence, publicCaseSummaryEvidence{
			State:       publicCaseTurkishState(row.State),
			Class:       row.Class,
			Relation:    publicCaseTurkishRelation(row),
			ObservedAt:  row.ObservedAt,
			Amount:      row.Amount,
			Source:      maskPublicDossierTarget(row.Source),
			Destination: maskPublicDossierTarget(row.Destination),
			Program:     row.Program,
			Slot:        row.Slot,
			Signature:   row.Signature,
		})
	}

	gradeExplanation := fmt.Sprintf("%s bir yüzde veya 0–100 puanı değildir ve tek başına güvenli anlamına gelmez. Bu vakada doğrulanmış/gözlenmiş bileşik kurallar başlangıç seviyesini bir kademe düşürdü.", data.VerdictGrade)
	return publicCaseSummaryPageData{
		Case:             data,
		OutcomeLabel:     outcomeLabel,
		OutcomeClass:     outcomeClass,
		OutcomeText:      outcomeText,
		GradeExplanation: gradeExplanation,
		Known:            known,
		Missing:          missing,
		Actions: []string{
			"Bu cüzdanı yalnız B harfini görerek güvenli kabul etme.",
			"Likidite, creator dağıtımı ve top-holder karşılaştırması tamamlanmadan yüksek tutarlı işlem yapma.",
			"Karar vermeden önce aşağıdaki işlem imzalarını ve ham değişmez dossier'ı bağımsız olarak doğrula.",
		},
		RuleReasons: ruleReasons,
		Evidence:    evidence,
	}
}

func publicCaseKnownText(signal publicCaseSignalView) string {
	switch strings.ToUpper(strings.TrimSpace(signal.ID)) {
	case "AC-01":
		return "Cüzdan soruşturma hedefi olarak kabul edildi."
	case "AC-02":
		return "Hedefin bir Solana cüzdanı olduğu doğrulandı."
	case "AC-03":
		return "Bu cüzdanın oluşturduğu token geçmişi zincir üstü kanıtlarla gözlendi."
	case "AC-04":
		return "İlk fonlama kaynağı bir zincir üstü işlemle doğrulandı."
	case "AC-05":
		return "Creator token çıkışları ve alıcı cüzdanlar çözümlendi."
	case "AC-06":
		return "Alıcı cüzdanlar top-holder verisiyle karşılaştırıldı."
	case "AC-07":
		return "Likidite ekleme veya çekme hareketleri imzalarla gösterildi."
	case "AC-08":
		return "Creator ve dominant-holder tekrarları farklı tokenlarda bulundu."
	case "AC-09":
		return "Creator ile dominant holder arasındaki doğrudan ilişki kanıtla sınırlandı."
	case "AC-10":
		return "Kanıt destekli deterministik sonuç kabul kontrolünü geçti."
	default:
		return firstPublicDossierString(signal.Summary, signal.Label)
	}
}

func publicCaseMissingText(signal publicCaseSignalView) string {
	switch strings.ToUpper(strings.TrimSpace(signal.ID)) {
	case "AC-05":
		return "Creator'ın tokenları hangi alıcı cüzdanlara dağıttığı tamamlanmadı."
	case "AC-06":
		return "Alıcı cüzdanların top holder olup olmadığı karşılaştırılmadı."
	case "AC-07":
		return "Likidite ekleme veya çekme hareketleri tam kanıtlanmadı."
	case "AC-08":
		return "Farklı tokenlarda creator + dominant-holder tekrar ilişkisi doğrulanmadı."
	case "AC-09":
		return "Creator ile dominant holder arasında doğrudan ilişki doğrulanmadı."
	case "AC-10":
		return "Üretilen harf notu kabul testinin bütün koşullarını karşılamadı."
	default:
		return firstPublicDossierString(signal.Summary, signal.Label+" tamamlanmadı.")
	}
}

func publicCaseRuleReason(rule publicCaseRuleView) string {
	switch strings.ToUpper(strings.TrimSpace(rule.ID)) {
	case "ARD-C003":
		return "Başka token yüzeylerinde ilişkili bir cüzdan tekrar görüldü. Bu gözlem tek başına ortak sahiplik veya suç kanıtı değildir."
	case "ARD-C004":
		return fmt.Sprintf("Aynı doğrudan transfer ilişkisi %d kez tekrarlandı. Tekrarlanan ilişki harf notuna bileşik risk girdisi olarak eklendi.", rule.Count)
	default:
		return fmt.Sprintf("%s kuralı tetiklendi: %s", rule.ID, firstPublicDossierString(rule.Summary, rule.Title))
	}
}

func publicCaseTurkishState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "verified":
		return "DOĞRULANDI"
	case "observed":
		return "GÖZLENDİ"
	case "inferred":
		return "ÇIKARIM"
	case "failed", "fail":
		return "BAŞARISIZ"
	default:
		return "TAMAMLANMADI"
	}
}

func publicCaseTurkishRelation(row publicCaseEvidenceView) string {
	value := strings.ToLower(strings.TrimSpace(firstPublicDossierString(row.Relation, row.RelationLabel)))
	switch {
	case strings.Contains(value, "sol") && strings.Contains(value, "out"):
		return "Cüzdandan SOL çıkışı"
	case strings.Contains(value, "sol") && strings.Contains(value, "in"):
		return "Cüzdana SOL girişi"
	case strings.Contains(value, "token") && strings.Contains(value, "out"):
		return "Cüzdandan token çıkışı"
	case strings.Contains(value, "token") && strings.Contains(value, "in"):
		return "Cüzdana token girişi"
	default:
		return firstPublicDossierString(row.RelationLabel, row.Relation, "Zincir üstü işlem")
	}
}

func compactPublicCaseStrings(values []string, limit int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

var publicCaseSummaryHTML = template.Must(template.New("public-case-summary").Parse(`<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="description" content="Koschei ARVIS tarafından yayınlanan sade Türkçe Solana güvenlik vaka özeti.">
<meta name="theme-color" content="#02050a">
<title>{{.Case.Title}} · Koschei ARVIS</title>
<link rel="stylesheet" href="/css/public-case-summary.css?v=1">
</head>
<body>
<main class="summary-shell">
<nav class="summary-nav"><a class="brand" href="/"><span>K</span><b>Koschei ARVIS<small>Herkes için anlaşılır vaka özeti</small></b></a><div><a href="/live">Canlı SOC</a><a href="/cases">Tüm vakalar</a><a class="technical" href="{{.Case.TechnicalURL}}">Ham teknik dossier</a></div></nav>

<header class="summary-hero">
<div><span class="eyebrow">{{.Case.TargetKind}} soruşturması {{if .Case.Featured}}· ÖNE ÇIKAN VAKA{{end}}</span><h1>Bu cüzdan hakkında ne biliyoruz?</h1><p class="lead">{{.OutcomeText}}</p><div class="target"><span>İncelenen adres</span><code>{{.Case.TargetID}}</code></div></div>
<aside class="outcome {{.OutcomeClass}}"><span>SONUÇ DURUMU</span><strong>{{.OutcomeLabel}}</strong><div class="grade"><b>{{.Case.VerdictGrade}}</b><p>{{.GradeExplanation}}</p></div><small>{{.Case.Acceptance.Pass}} kontrol geçti · {{.Case.Acceptance.Fail}} başarısız · {{.Case.Acceptance.NotInvestigated}} tamamlanmadı</small></aside>
</header>

<section class="plain-grid">
<article class="plain-card known"><span>NE BULDUK?</span><h2>Doğrulanan ve gözlenenler</h2><ul>{{range .Known}}<li>{{.}}</li>{{else}}<li>Bu dosyada müşteriye sunulabilecek doğrulanmış bulgu yok.</li>{{end}}</ul></article>
<article class="plain-card missing"><span>NE BULAMADIK?</span><h2>Eksik kalan araştırmalar</h2><ul>{{range .Missing}}<li>{{.}}</li>{{else}}<li>Kabul kapsamındaki bütün alanlar tamamlandı.</li>{{end}}</ul></article>
<article class="plain-card action"><span>NE YAPMALI?</span><h2>Karar vermeden önce</h2><ol>{{range .Actions}}<li>{{.}}</li>{{end}}</ol></article>
</section>

<section class="explain-panel"><div class="section-head"><div><span class="eyebrow">NEDEN BU SONUÇ ÇIKTI?</span><h2>B harfi nereden geldi?</h2></div><span class="pill">{{len .RuleReasons}} kural</span></div><div class="reason-list">{{range .RuleReasons}}<p>{{.}}</p>{{end}}</div><p class="warning"><b>Önemli:</b> B notu “güvenli” etiketi değildir. Bu rapor teknik ilişki ve kapasiteyi gösterir; gerçek kişi, niyet veya suç isnadı yapmaz.</p></section>

<details class="technical-details"><summary><span><b>ARVIS evidence coverage</b><small>10 kabul kontrolünün teknik ayrıntılarını aç</small></span><i>+</i></summary><div class="coverage-simple">{{range .Case.Signals}}<article class="{{.StateClass}}"><div><code>{{.ID}}</code><b>{{.Label}}</b></div><span>{{.State}}</span><p>{{.Summary}}</p></article>{{end}}</div></details>

<details class="technical-details"><summary><span><b>Evidence timeline</b><small>Son 8 doğrulanabilir işlem satırını aç</small></span><i>+</i></summary><div class="evidence-list">{{range .Evidence}}<article><div><span class="state {{.Class}}">{{.State}}</span><b>{{.Relation}}</b><small>{{.ObservedAt}}</small></div><dl><div><dt>Kaynak → hedef</dt><dd><code>{{.Source}} → {{.Destination}}</code></dd></div><div><dt>Miktar</dt><dd>{{.Amount}}</dd></div><div><dt>Program / slot</dt><dd>{{.Program}} · {{.Slot}}</dd></div></dl>{{if .Signature}}<a href="https://solscan.io/tx/{{.Signature}}" rel="noreferrer">Solscan'de doğrula ↗</a>{{end}}</article>{{else}}<p>Görünür işlem satırı yok.</p>{{end}}</div></details>

<section class="integrity"><div><span>Vaka referansı</span><code>{{.Case.CaseRef}}</code></div><div><span>Bundle hash</span><code>{{.Case.BundleHash}}</code></div><div><span>Ruleset</span><code>{{.Case.RulesetVersion}}</code></div><div><span>Üretim zamanı</span><b>{{.Case.ProducedAt.Format "02 Jan 2006 · 15:04 UTC"}}</b></div></section>

<section class="boundaries"><h2>Bu rapor ne iddia etmez?</h2><ul><li>Bu cüzdanın gerçek hayatta kime ait olduğunu söylemez.</li><li>Kötü niyet, dolandırıcılık veya suç isnadı yapmaz.</li><li>Eksik araştırılmış alanları güvenli kabul etmez.</li><li>Yatırım tavsiyesi veya otomatik işlem onayı değildir.</li></ul><div class="buttons"><a href="/cases">Vaka listesine dön</a><a class="primary" href="{{.Case.TechnicalURL}}">Ham teknik dossier</a></div></section>
</main>
</body>
</html>`))
