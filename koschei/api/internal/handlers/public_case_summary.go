package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"
)

type publicCaseSummaryPageData struct {
	Case             publicCasePageData
	TargetLabel      string
	DecisionLabel    string
	DecisionClass    string
	DecisionText     string
	GradeDisplay     string
	GradeExplanation string
	Findings         []string
	Reasons          []string
	Actions          []string
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

// PublicCaseSummaryPage is the customer-facing security result. Internal
// acceptance controls, collector names and worker state stay out of the public
// product surface; the immutable dossier remains available for verification.
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

	data := buildPublicCaseSummaryPageData(buildPublicCasePageData(bundle, title, summary, featured, publishedAt))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60, stale-while-revalidate=300")
	w.Header().Set("X-Robots-Tag", "index, follow")
	if err := publicCaseSummaryHTML.Execute(w, data); err != nil {
		http.Error(w, "public case summary render failed", http.StatusInternalServerError)
	}
}

func buildPublicCaseSummaryPageData(data publicCasePageData) publicCaseSummaryPageData {
	gradeDisplay := publicCaseEffectiveGrade(data)
	decisionLabel, decisionClass, decisionText := publicCaseDecision(data, gradeDisplay)

	findings := make([]string, 0, len(data.Signals)+len(data.Rules))
	for _, signal := range data.Signals {
		if signal.StateClass == "verified" || signal.StateClass == "observed" {
			findings = append(findings, publicCaseKnownText(signal))
		}
	}
	findings = compactPublicCaseStrings(findings, 6)
	if len(findings) == 0 {
		findings = []string{"Bu vaka için halka açık doğrulanmış veya gözlenmiş güvenlik bulgusu bulunmuyor."}
	}

	reasons := publicCaseCollapsedRuleReasons(data.Rules)
	if len(reasons) == 0 {
		reasons = []string{"Karar, yayımlanan değişmez kanıt paketi ve imzalı deterministik sonuç sözleşmesine dayanır."}
	}

	evidence := make([]publicCaseSummaryEvidence, 0, 6)
	for index, row := range data.Evidence {
		if index >= 6 {
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

	return publicCaseSummaryPageData{
		Case:             data,
		TargetLabel:      publicCaseTargetLabel(data.TargetKind),
		DecisionLabel:    decisionLabel,
		DecisionClass:    decisionClass,
		DecisionText:     decisionText,
		GradeDisplay:     gradeDisplay,
		GradeExplanation: publicCaseGradeExplanation(gradeDisplay),
		Findings:         findings,
		Reasons:          reasons,
		Actions:          publicCaseActions(decisionLabel),
		Evidence:         evidence,
	}
}

func publicCaseEffectiveGrade(data publicCasePageData) string {
	grade := strings.ToUpper(strings.TrimSpace(data.VerdictGrade))
	status := strings.ToLower(strings.TrimSpace(data.VerdictStatus))
	if grade == "" || grade == "-" || strings.Contains(status, "withhold") {
		return "WITHHOLD"
	}
	for _, signal := range data.Signals {
		if strings.EqualFold(strings.TrimSpace(signal.ID), "AC-10") && !strings.EqualFold(strings.TrimSpace(signal.AcceptanceStatus), "pass") {
			return "WITHHOLD"
		}
	}
	return grade
}

func publicCaseDecision(data publicCasePageData, grade string) (string, string, string) {
	status := strings.ToLower(strings.TrimSpace(data.VerdictStatus))
	switch {
	case grade == "WITHHOLD" || strings.Contains(status, "withhold"):
		return "İŞLEMİ BEKLET", "withhold", "Kanıt sözleşmesi bu vaka için işlem onayı üretmiyor. İmzalamadan veya varlık göndermeden önce doğrulanabilir kanıtı incele."
	case strings.Contains(status, "block") || grade == "F" || grade == "D":
		return "BLOKLA", "block", "Kanıt destekli yüksek risk işaretleri var. Bu hedefle işlem kurma veya imza verme."
	case strings.Contains(status, "warn") || strings.Contains(status, "review") || grade == "C" || grade == "B":
		return "YÜKSEK DİKKAT", "warn", "Doğrulanmış risk işaretleri var. İşlemi yalnız kanıtları bağımsız doğruladıktan sonra değerlendir."
	case strings.Contains(status, "allow") || grade == "A":
		return "KANITLA DEVAM", "allow", "Mevcut kanıt belirlenen sert engel kurallarını tetiklemedi. Bu sonuç güvenlik garantisi değildir; işlem ayrıntılarını yine doğrula."
	default:
		return "İŞLEMİ BEKLET", "withhold", "Karar durumu açık bir işlem onayı üretmiyor. Kanıtı doğrulamadan imza verme."
	}
}

func publicCaseGradeExplanation(grade string) string {
	if grade == "WITHHOLD" {
		return "WITHHOLD, güvenli veya tehlikeli etiketi değil; kanıt sınırı nedeniyle işlem onayının verilmediği anlamına gelir."
	}
	return grade + " harfi bir yüzde veya 0–100 puanı değildir. Yalnız yayımlanan deterministik kanıt sözleşmesinin sonucudur."
}

func publicCaseTargetLabel(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "wallet", "actor":
		return "Cüzdan"
	case "token", "token_mint", "mint":
		return "Token"
	case "program", "solana_program":
		return "Program"
	default:
		return "Hedef"
	}
}

func publicCaseActions(decision string) []string {
	switch decision {
	case "BLOKLA":
		return []string{"İşlemi imzalama ve hedefe varlık gönderme.", "Program, cüzdan veya token adresini uygulamandaki engel listesine ekle.", "Aşağıdaki imzaları ve değişmez dossier hash'ini bağımsız olarak doğrula."}
	case "YÜKSEK DİKKAT":
		return []string{"Yüksek tutarlı işlem yapma; önce küçük ve geri döndürülebilir doğrulama kullan.", "Karşı taraf, program authority ve işlem talimatlarını bağımsız kaynaktan doğrula.", "Aşağıdaki zincir üstü kanıtları incelemeden imza verme."}
	case "KANITLA DEVAM":
		return []string{"İşlem talimatlarını, program adresini ve harcama yetkilerini tekrar kontrol et.", "Sonucun yalnız bu kanıt anına ait olduğunu unutma.", "Şüpheli bir değişiklik görürsen işlemi durdur ve yeniden tara."}
	default:
		return []string{"İşlemi şimdilik imzalama.", "Aşağıdaki kanıtı ve ham dossier hash'ini doğrula.", "Yeni ve imzalı bir karar oluşmadan bu hedefi güvenli kabul etme."}
	}
}

func publicCaseCollapsedRuleReasons(rules []publicCaseRuleView) []string {
	type aggregate struct {
		rule  publicCaseRuleView
		count int
	}
	groups := map[string]aggregate{}
	order := []string{}
	for _, rule := range rules {
		id := strings.ToUpper(strings.TrimSpace(rule.ID))
		if id == "" {
			id = strings.ToUpper(strings.TrimSpace(rule.Title))
		}
		item, exists := groups[id]
		if !exists {
			item.rule = rule
			order = append(order, id)
		}
		count := rule.Count
		if count <= 0 {
			count = 1
		}
		item.count += count
		groups[id] = item
	}
	sort.Strings(order)
	out := make([]string, 0, len(order))
	for _, id := range order {
		item := groups[id]
		item.rule.Count = item.count
		out = append(out, publicCaseRuleReason(item.rule))
	}
	return compactPublicCaseStrings(out, 6)
}

func publicCaseKnownText(signal publicCaseSignalView) string {
	switch strings.ToUpper(strings.TrimSpace(signal.ID)) {
	case "AC-01":
		return "Hedef adres geçerli bir inceleme hedefi olarak doğrulandı."
	case "AC-02":
		return "Hedefin Solana üzerindeki hesap türü zincirden doğrulandı."
	case "AC-03":
		return "Hedefle bağlantılı token oluşturma geçmişi zincir üstü kanıtlarla gözlendi."
	case "AC-04":
		return "İlk fonlama kaynağı işlem imzası ve slot bilgisiyle doğrulandı."
	case "AC-05":
		return "Token dağıtımı ve alıcı hesaplar zincir üstü hareketlerle çözümlendi."
	case "AC-06":
		return "Alıcı hesaplar holder verisiyle karşılaştırıldı."
	case "AC-07":
		return "Likidite ekleme veya çekme hareketleri işlem kanıtıyla gösterildi."
	case "AC-08":
		return "Aynı aktör örüntüsünün birden fazla token yüzeyinde tekrarı gözlendi."
	case "AC-09":
		return "Doğrudan hesap ilişkisi işlem kanıtıyla sınırlandı."
	case "AC-10":
		return "Deterministik kararın kanıt ve imza bağı doğrulandı."
	default:
		return firstPublicDossierString(signal.Summary, signal.Label)
	}
}

func publicCaseRuleReason(rule publicCaseRuleView) string {
	switch strings.ToUpper(strings.TrimSpace(rule.ID)) {
	case "ARD-C003":
		return fmt.Sprintf("İlişkili hesap örüntüsü farklı token yüzeylerinde %d kez gözlendi. Bu teknik bağ tek başına kimlik veya suç kanıtı değildir.", maxPublicCaseInt(rule.Count, 1))
	case "ARD-C004":
		return fmt.Sprintf("Aynı doğrudan transfer ilişkisi toplam %d doğrulanmış işlemde tekrarlandı.", maxPublicCaseInt(rule.Count, 1))
	default:
		return fmt.Sprintf("%s: %s", firstPublicDossierString(rule.ID, "Kural"), firstPublicDossierString(rule.Summary, rule.Title, "Kanıt destekli kural tetiklendi."))
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
		return "DOĞRULANAMADI"
	default:
		return "BİLİNMİYOR"
	}
}

func publicCaseTurkishRelation(row publicCaseEvidenceView) string {
	value := strings.ToLower(strings.TrimSpace(firstPublicDossierString(row.Relation, row.RelationLabel)))
	switch {
	case strings.Contains(value, "sol") && strings.Contains(value, "out"):
		return "SOL çıkışı"
	case strings.Contains(value, "sol") && strings.Contains(value, "in"):
		return "SOL girişi"
	case strings.Contains(value, "token") && strings.Contains(value, "out"):
		return "Token çıkışı"
	case strings.Contains(value, "token") && strings.Contains(value, "in"):
		return "Token girişi"
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
<meta name="description" content="Koschei ARVIS kanıt destekli Solana güvenlik sonucu.">
<meta name="theme-color" content="#02050a">
<title>{{.Case.Title}} · Koschei ARVIS</title>
<link rel="stylesheet" href="/css/public-case-summary.css?v=3">
</head>
<body>
<main class="summary-shell">
<nav class="summary-nav"><a class="brand" href="/"><span>K</span><b>Koschei ARVIS<small>Herkese açık Solana güvenliği</small></b></a><div><a href="/live">Canlı Radar</a><a href="/cases">Vakalar</a><a class="technical" href="{{.Case.TechnicalURL}}">Kanıt dosyası</a></div></nav>
<header class="summary-hero">
<div><span class="eyebrow">{{.TargetLabel}} GÜVENLİK SONUCU {{if .Case.Featured}}· ÖNE ÇIKAN{{end}}</span><h1>{{.DecisionLabel}}</h1><p class="lead">{{.DecisionText}}</p><div class="target"><span>İncelenen hedef</span><code>{{.Case.TargetID}}</code></div></div>
<aside class="outcome {{.DecisionClass}}"><span>ARVIS KARARI</span><strong>{{.DecisionLabel}}</strong><div class="grade"><b class="{{if eq .GradeDisplay "WITHHOLD"}}word{{end}}">{{.GradeDisplay}}</b><p>{{.GradeExplanation}}</p></div><small>{{.Case.ProducedAt.Format "02 Jan 2006 · 15:04 UTC"}} · {{.Case.Network}}</small></aside>
</header>
<section class="plain-grid">
<article class="plain-card known"><span>NE BULDUK?</span><h2>Kanıtlanmış bulgular</h2><ul>{{range .Findings}}<li>{{.}}</li>{{end}}</ul></article>
<article class="plain-card reason"><span>NEDEN ÖNEMLİ?</span><h2>Kararı etkileyen örüntüler</h2><ul>{{range .Reasons}}<li>{{.}}</li>{{end}}</ul></article>
<article class="plain-card action"><span>NE YAPMALISIN?</span><h2>Uygulanacak eylem</h2><ol>{{range .Actions}}<li>{{.}}</li>{{end}}</ol></article>
</section>
<section class="explain-panel"><div class="section-head"><div><span class="eyebrow">ZİNCİR ÜSTÜ KANIT</span><h2>Doğrulanabilir işlemler</h2></div><span class="pill">{{len .Evidence}} satır</span></div><div class="evidence-list">{{range .Evidence}}<article><div><span class="state {{.Class}}">{{.State}}</span><b>{{.Relation}}</b><small>{{.ObservedAt}}</small></div><dl><div><dt>Kaynak → hedef</dt><dd><code>{{.Source}} → {{.Destination}}</code></dd></div><div><dt>Miktar</dt><dd>{{.Amount}}</dd></div><div><dt>Program / slot</dt><dd>{{.Program}} · {{.Slot}}</dd></div></dl>{{if .Signature}}<a href="https://solscan.io/tx/{{.Signature}}" rel="noreferrer">Solscan'de doğrula ↗</a>{{end}}</article>{{else}}<p class="empty">Bu public görünümde işlem satırı yok. Değişmez kanıt dosyasını aç.</p>{{end}}</div></section>
<section class="integrity"><div><span>Vaka referansı</span><code>{{.Case.CaseRef}}</code></div><div><span>Bundle hash</span><code>{{.Case.BundleHash}}</code></div><div><span>Ruleset</span><code>{{.Case.RulesetVersion}}</code></div><div><span>İmzalı sonuç</span><code>{{.Case.Signature}}</code></div></section>
<section class="boundaries"><h2>Kanıt sınırı</h2><p>Bu sonuç gerçek kişi kimliği, niyet veya suç isnadı değildir. Harf notu 0–100 puanı değildir. Karar yalnız yayımlanan zincir üstü kanıt ve sürümlü deterministik kurallara dayanır.</p><div class="buttons"><a href="/cases">Vakalara dön</a><a class="primary" href="{{.Case.TechnicalURL}}">Değişmez kanıt dosyasını aç</a></div></section>
</main>
</body>
</html>`))
