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

type publicCaseOperationalPageData struct {
	Case             publicCasePageData
	OutcomeLabel     string
	OutcomeClass     string
	OutcomeText      string
	GradeDisplay     string
	GradeExplanation string
	Completed        []string
	Jobs             []publicCaseOperationalJob
	RuleReasons      []string
	Evidence         []publicCaseOperationalEvidence
	VanityClusters   []publicCaseVanityCluster
}

type publicCaseOperationalJob struct {
	ID              string
	Title           string
	State           string
	Class           string
	Worker          string
	AutomaticAction string
	Reason          string
	UserRequirement string
}

type publicCaseOperationalEvidence struct {
	State               string
	Class               string
	Relation            string
	ObservedAt          string
	Amount              string
	Source              string
	Destination         string
	Program             string
	Slot                string
	Signature           string
	Classification      string
	ClassificationClass string
}

type publicCaseVanityCluster struct {
	Pattern        string
	MatchType      string
	State          string
	Class          string
	Addresses      []string
	AddressCount   int
	SignatureCount int
	Limitation     string
}

// PublicCaseOperationalPage renders the customer-facing case as an ARVIS work
// status, not as homework for the visitor. The immutable dossier remains the
// source of truth and is never changed by this projection.
func (h *Handler) PublicCaseOperationalPage(w http.ResponseWriter, r *http.Request) {
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
	data := buildPublicCaseOperationalPageData(technical)
	data.Evidence = publicCaseOperationalEvidenceRows(bundle.EvidenceLog, 5)
	data.VanityClusters = publicCaseOperationalVanityClusters(bundle.CrossTokenConnections)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60, stale-while-revalidate=300")
	w.Header().Set("X-Robots-Tag", "index, follow")
	if err := publicCaseOperationalHTML.Execute(w, data); err != nil {
		http.Error(w, "public case operational render failed", http.StatusInternalServerError)
	}
}

func buildPublicCaseOperationalPageData(data publicCasePageData) publicCaseOperationalPageData {
	completed := []string{}
	jobs := []publicCaseOperationalJob{}
	for _, signal := range data.Signals {
		status := strings.ToLower(strings.TrimSpace(signal.AcceptanceStatus))
		if status == "pass" {
			completed = append(completed, publicCaseKnownText(signal))
			continue
		}
		jobs = append(jobs, publicCaseOperationalJobForSignal(signal))
	}
	completed = compactPublicCaseStrings(completed, 6)

	outcomeLabel := "SONUÇ BEKLETİLİYOR"
	outcomeClass := "review"
	outcomeText := fmt.Sprintf(
		"Bu dosya tamamlanmış bir karar değildir. ARVIS kabul zincirinde %d kanıt üretilemeyen ve %d henüz çalıştırılmamış otomatik kontrol bulunuyor. Bunlar müşteriye bırakılan manuel inceleme değil, Koschei worker görevleridir.",
		data.Acceptance.Fail, data.Acceptance.NotInvestigated,
	)
	if len(jobs) == 0 && data.Acceptance.Fail == 0 && data.Acceptance.NotInvestigated == 0 {
		outcomeLabel = "KANIT KAPSAMI TAMAM"
		outcomeClass = "complete"
		outcomeText = "Kabul kapsamındaki otomatik ARVIS kontrolleri tamamlandı. Sonuç yine yalnız zincir üstü teknik kanıta dayanır; gerçek kişi, niyet veya suç isnadı değildir."
	}

	gradeDisplay := strings.TrimSpace(data.VerdictGrade)
	if gradeDisplay == "" || gradeDisplay == "-" {
		gradeDisplay = "WITHHOLD"
	}
	gradeExplanation := "Harf notu veya WITHHOLD sonucu bir yüzde, 0–100 puanı ya da güvenli etiketi değildir. Açık otomatik işler varken Koschei işlem onayı üretmez."

	ruleReasons := make([]string, 0, len(data.Rules))
	for _, rule := range data.Rules {
		ruleReasons = append(ruleReasons, publicCaseRuleReason(rule))
	}
	if len(ruleReasons) == 0 {
		ruleReasons = append(ruleReasons, "Bu snapshot içinde kanıt destekli grade-changing kural yok; sonuç bu nedenle WITHHOLD kalabilir.")
	}

	evidence := make([]publicCaseOperationalEvidence, 0, 5)
	for index, row := range data.Evidence {
		if index >= 5 {
			break
		}
		evidence = append(evidence, publicCaseOperationalEvidence{
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

	return publicCaseOperationalPageData{
		Case:             data,
		OutcomeLabel:     outcomeLabel,
		OutcomeClass:     outcomeClass,
		OutcomeText:      outcomeText,
		GradeDisplay:     gradeDisplay,
		GradeExplanation: gradeExplanation,
		Completed:        completed,
		Jobs:             jobs,
		RuleReasons:      ruleReasons,
		Evidence:         evidence,
	}
}

func publicCaseOperationalEvidenceRows(raw any, limit int) []publicCaseOperationalEvidence {
	items := dossierSlice(raw)
	type sortable struct {
		row  publicCaseOperationalEvidence
		when time.Time
	}
	rows := make([]sortable, 0, len(items))
	for _, item := range items {
		evidence := dossierMap(item)
		state := firstPublicDossierString(dossierString(evidence["verification_status"]), "unknown")
		when := publicCaseTime(evidence["observed_at"])
		if when.IsZero() {
			when = publicCaseTime(evidence["timestamp"])
		}
		view := publicCaseEvidenceView{
			Relation:      dossierString(evidence["relation"]),
			RelationLabel: publicCaseHumanLabel(dossierString(evidence["relation"])),
		}
		classification := ""
		classificationClass := ""
		possibleDust := publicCaseOperationalBool(evidence["possible_dust"])
		poisoning := publicCaseOperationalBool(evidence["address_poisoning_candidate"])
		if possibleDust && poisoning {
			classification = "POSSIBLE DUST · ADDRESS POISONING CANDIDATE · GRADE DIŞI"
			classificationClass = "dust"
		} else if possibleDust {
			classification = "POSSIBLE DUST · GRADE DIŞI"
			classificationClass = "dust"
		}
		rows = append(rows, sortable{row: publicCaseOperationalEvidence{
			State:               publicCaseTurkishState(state),
			Class:               publicCaseStateClass(state),
			Relation:            publicCaseTurkishRelation(view),
			ObservedAt:          publicCaseTimeText(when),
			Amount:              publicCaseEvidenceAmount(evidence),
			Source:              maskPublicDossierTarget(firstPublicDossierString(dossierString(evidence["source_wallet"]), dossierString(evidence["actor_wallet"]))),
			Destination:         maskPublicDossierTarget(firstPublicDossierString(dossierString(evidence["destination_wallet"]), dossierString(evidence["counterpart_id"]), dossierString(evidence["token_mint"]))),
			Program:             dossierString(evidence["program"]),
			Slot:                publicCaseNumber(evidence["slot"]),
			Signature:           dossierString(evidence["signature"]),
			Classification:      classification,
			ClassificationClass: classificationClass,
		}, when: when})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].when.After(rows[j].when) })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	out := make([]publicCaseOperationalEvidence, 0, len(rows))
	for _, item := range rows {
		out = append(out, item.row)
	}
	return out
}

func publicCaseOperationalVanityClusters(raw any) []publicCaseVanityCluster {
	connections := dossierMap(raw)
	items := dossierSlice(connections["address_similarity_clusters"])
	out := make([]publicCaseVanityCluster, 0, len(items))
	for _, item := range items {
		cluster := dossierMap(item)
		state := firstPublicDossierString(dossierString(cluster["verification_status"]), "inferred")
		addresses := publicCaseStrings(cluster["addresses"])
		out = append(out, publicCaseVanityCluster{
			Pattern:        dossierString(cluster["pattern"]),
			MatchType:      publicCaseHumanLabel(dossierString(cluster["match_type"])),
			State:          publicCaseTurkishState(state),
			Class:          publicCaseStateClass(state),
			Addresses:      addresses,
			AddressCount:   maxPublicCaseInt(len(addresses), publicDossierInt(cluster["address_count"])),
			SignatureCount: publicDossierInt(cluster["distinct_signature_count"]),
			Limitation:     firstPublicDossierString(dossierString(cluster["limitation"]), "Görsel adres benzerliği kimlik, sahiplik veya ortak kontrol kanıtı değildir."),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Pattern != out[j].Pattern {
			return out[i].Pattern < out[j].Pattern
		}
		return out[i].MatchType < out[j].MatchType
	})
	return out
}

func publicCaseOperationalBool(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return false
	}
}

func publicCaseOperationalJobForSignal(signal publicCaseSignalView) publicCaseOperationalJob {
	job := publicCaseOperationalJob{
		ID:              strings.ToUpper(strings.TrimSpace(signal.ID)),
		Title:           publicCaseOperationalTitle(signal.ID),
		Worker:          "ARVIS Evidence Orchestrator",
		AutomaticAction: "Eksik canonical kanıt satırını yeniden üretip kabul sözleşmesini tekrar değerlendirecek.",
		Reason:          publicCaseOperationalReason(signal.ID),
		UserRequirement: "Yok. Kullanıcıdan manuel zincir analizi beklenmez.",
	}
	switch strings.ToLower(strings.TrimSpace(signal.AcceptanceStatus)) {
	case "fail":
		job.State = "KANIT ÜRETİLEMEDİ"
		job.Class = "failed"
	default:
		job.State = "OTOMATİK İŞ AÇIK"
		job.Class = "queued"
	}

	switch job.ID {
	case "AC-04":
		job.Worker = "ARVIS Funding Origin Worker"
		job.AutomaticAction = "Cüzdanın eski imza sayfalarını tarayıp source → wallet funding işlemini imza, slot, zaman, miktar ve program alanlarıyla canonical satıra dönüştürecek."
	case "AC-05":
		job.Worker = "ARVIS Distribution Worker"
		job.AutomaticAction = "Creator rolündeki mintler için yalnız mint-spesifik token hesaplarının geçmişini tarayıp ilk/alınan recipient cüzdanlarını çıkaracak."
	case "AC-06":
		job.Worker = "ARVIS Holder Intelligence Worker"
		job.AutomaticAction = "Token supply, largest accounts ve owner-wallet çözümlemesini tamamlayıp recipient cüzdanlarını güncel top-holder snapshot'ıyla karşılaştıracak."
	case "AC-07":
		job.Worker = "ARVIS Liquidity Intelligence Worker"
		job.AutomaticAction = "Creator bağlantılı mintlerin DEX/pool işlemlerinde likidite ekleme ve çekme imzalarını, pool hesabını ve program kimliğini birlikte doğrulayacak."
		job.UserRequirement = "Yok. Bu, Koschei'nin collector/worker kapsamıdır; müşterinin manuel görevi değildir."
	case "AC-08":
		job.Worker = "ARVIS Cross-Token Correlator"
		job.AutomaticAction = "Creator ve owner-resolved dominant-holder tekrarlarını birden fazla mintte aynı canonical evidence key'lerine bağlayacak."
	case "AC-09":
		job.Worker = "ARVIS Direct Relation Resolver"
		job.AutomaticAction = "Creator → dominant-holder doğrudan SOL/token transferini kanıtlayacak veya açıkça NOT VERIFIED olarak sınırlandıracak."
	case "AC-10":
		job.Worker = "ARVIS Deterministic Verdict Engine"
		job.AutomaticAction = "Grade-changing her kuralın evidence_key ve signature bağını doğrulayıp verdict'i yeniden imzalayacak; bağ yoksa harf notunu geri çekecek."
	}
	return job
}

func publicCaseOperationalTitle(id string) string {
	switch strings.ToUpper(strings.TrimSpace(id)) {
	case "AC-04":
		return "İlk fonlama kanıtını tamamla"
	case "AC-05":
		return "Creator token dağıtımını çöz"
	case "AC-06":
		return "Recipient ↔ top-holder karşılaştırmasını tamamla"
	case "AC-07":
		return "Likidite ekleme/çekme izini tamamla"
	case "AC-08":
		return "Cross-token creator/holder tekrarını kanıtla"
	case "AC-09":
		return "Doğrudan creator/holder ilişkisini sınırla"
	case "AC-10":
		return "Verdict kanıt bütünlüğünü doğrula"
	default:
		return "Kabul kontrolünü tamamla"
	}
}

func publicCaseOperationalReason(id string) string {
	switch strings.ToUpper(strings.TrimSpace(id)) {
	case "AC-04":
		return "Bu snapshot'ta funding collector gerekli source, destination, signature, slot, zaman ve program alanlarının tamamını taşıyan tek canonical satır üretemedi."
	case "AC-05":
		return "Bu snapshot'ta mint-spesifik creator token-account geçmişinden tamamlanmış recipient kanıtı bulunmuyor."
	case "AC-06":
		return "Recipient kanıtı ile tamamlanmış supply/largest-account/owner çözümleme kaynağı aynı kabul çalışmasında birleşmedi."
	case "AC-07":
		return "Mevcut dar wallet taraması mint → pool likidite add/remove yüzeyini tam kapsamadı veya explicit pool/program kanıtı üretmedi."
	case "AC-08":
		return "Sayaç veya gözlem bulunsa bile creator + dominant-holder tekrar şartı canonical evidence key'leriyle tam doğrulanmadı."
	case "AC-09":
		return "Doğrudan creator → dominant-holder transferi için gereken owner-resolved karşı taraf ve transaction kanıtı birlikte bulunmadı."
	case "AC-10":
		return "Grade-changing kurallardan en az biri canonical evidence_key/signature bağı olmadan verdict'e girdi veya imzalı verdict sözleşmesi tamamlanmadı."
	default:
		return "Kabul kontrolünün zorunlu canonical kanıt koşulu bu snapshot'ta sağlanmadı."
	}
}

var publicCaseOperationalHTML = template.Must(template.New("public-case-operational").Parse(`<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="description" content="Koschei ARVIS otomatik Solana güvenlik soruşturması ve açık worker durumları.">
<meta name="theme-color" content="#02050a">
<title>{{.Case.Title}} · Koschei ARVIS</title>
<link rel="stylesheet" href="/css/public-case-summary.css?v=1">
<link rel="stylesheet" href="/css/public-case-operational.css?v=2">
</head>
<body>
<main class="summary-shell">
<nav class="summary-nav"><a class="brand" href="/"><span>K</span><b>Koschei ARVIS<small>Otomatik soruşturma durumu</small></b></a><div><a href="/live">Canlı SOC</a><a href="/cases">Tüm vakalar</a><a class="technical" href="{{.Case.TechnicalURL}}">Ham teknik dossier</a></div></nav>

<header class="summary-hero">
<div><span class="eyebrow">{{.Case.TargetKind}} soruşturması {{if .Case.Featured}}· ÖNE ÇIKAN VAKA{{end}}</span><h1>ARVIS bu cüzdan için neyi tamamladı, neyi tamamlayacak?</h1><p class="lead">{{.OutcomeText}}</p><div class="target"><span>İncelenen adres</span><code>{{.Case.TargetID}}</code></div></div>
<aside class="outcome {{.OutcomeClass}}"><span>SONUÇ DURUMU</span><strong>{{.OutcomeLabel}}</strong><div class="grade"><b>{{.GradeDisplay}}</b><p>{{.GradeExplanation}}</p></div><small>{{.Case.Acceptance.Pass}} otomatik kontrol tamamlandı · {{.Case.Acceptance.Fail}} kanıt üretemedi · {{.Case.Acceptance.NotInvestigated}} worker kapsamı açık</small></aside>
</header>

<section class="operational-grid">
<article class="plain-card known"><span>TAMAMLANANLAR</span><h2>ARVIS'in kanıtladığı alanlar</h2><ul>{{range .Completed}}<li>{{.}}</li>{{else}}<li>Bu snapshot'ta tamamlanmış kabul kontrolü yok.</li>{{end}}</ul></article>
<article class="plain-card action system-owner"><span>SORUMLULUK KİMDE?</span><h2>Koschei worker'larında</h2><p>Müşteri veya site ziyaretçisi zincir analizi yapmak zorunda değildir. Açık kontroller ARVIS collector ve worker'larının işidir.</p><ul><li>Kullanıcıdan özel anahtar veya manuel RPC çalıştırması istenmez.</li><li>Kanıt oluşmadan güvenli/tehlikeli sonucu verilmez.</li><li>Worker tamamlandığında yeni immutable vaka sürümü üretilir.</li></ul></article>
</section>

<section class="explain-panel work-panel"><div class="section-head"><div><span class="eyebrow">ARVIS ŞİMDİ NE YAPACAK?</span><h2>Açık otomatik işler</h2></div><span class="pill">{{len .Jobs}} iş</span></div><div class="job-list">{{range .Jobs}}<article class="job {{.Class}}"><div class="job-head"><code>{{.ID}}</code><span>{{.State}}</span></div><h3>{{.Title}}</h3><dl><div><dt>Sorumlu worker</dt><dd>{{.Worker}}</dd></div><div><dt>Otomatik işlem</dt><dd>{{.AutomaticAction}}</dd></div><div><dt>Neden açık?</dt><dd>{{.Reason}}</dd></div><div><dt>Kullanıcıdan gereken</dt><dd>{{.UserRequirement}}</dd></div></dl></article>{{else}}<div class="empty">Açık otomatik iş yok; acceptance kapsamı tamamlandı.</div>{{end}}</div></section>

<section class="explain-panel"><div class="section-head"><div><span class="eyebrow">MEVCUT TEKNİK SONUÇ</span><h2>Verdict nasıl oluştu?</h2></div><span class="pill">{{len .RuleReasons}} kural</span></div><div class="reason-list">{{range .RuleReasons}}<p>{{.}}</p>{{end}}</div><p class="warning"><b>Önemli:</b> Harf notu “güvenli” etiketi değildir. Açık worker işleri varsa Koschei sonucu bekletir; gerçek kişi, niyet veya suç isnadı yapmaz.</p></section>

<details class="technical-details"><summary><span><b>ARVIS evidence coverage</b><small>10 kabul kontrolünün teknik ayrıntılarını aç</small></span><i>+</i></summary><div class="coverage-simple">{{range .Case.Signals}}<article class="{{.StateClass}}"><div><code>{{.ID}}</code><b>{{.Label}}</b></div><span>{{.AcceptanceStatus}}</span><p>{{.Summary}}</p></article>{{end}}</div></details>

{{if .VanityClusters}}<details class="technical-details vanity-details"><summary><span><b>Vanity adres benzerliği</b><small>{{len .VanityClusters}} INFERRED küme · Tümünü göster</small></span><i>+</i></summary><p class="vanity-boundary">Bu alan yalnız Base58 görsel benzerliğini gösterir. Aynı kişi, sahiplik, niyet veya ortak kontrol kanıtı değildir ve grade'i değiştirmez.</p><div class="vanity-list">{{range .VanityClusters}}<article><div class="vanity-head"><code>{{.Pattern}}</code><span class="state {{.Class}}">{{.State}}</span></div><p>{{.MatchType}} · {{.AddressCount}} adres · {{.SignatureCount}} benzersiz işlem imzası</p><div class="vanity-addresses">{{range .Addresses}}<code>{{.}}</code>{{end}}</div><small>{{.Limitation}}</small></article>{{end}}</div></details>{{end}}

<details class="technical-details"><summary><span><b>Evidence timeline</b><small>Son 5 doğrulanabilir işlem satırını aç</small></span><i>+</i></summary><div class="evidence-list">{{range .Evidence}}<article><div><span class="state {{.Class}}">{{.State}}</span><b>{{.Relation}}</b><small>{{.ObservedAt}}</small>{{if .Classification}}<em class="evidence-classification {{.ClassificationClass}}">{{.Classification}}</em>{{end}}</div><dl><div><dt>Kaynak → hedef</dt><dd><code>{{.Source}} → {{.Destination}}</code></dd></div><div><dt>Miktar</dt><dd>{{.Amount}}</dd></div><div><dt>Program / slot</dt><dd>{{.Program}} · {{.Slot}}</dd></div></dl>{{if .Signature}}<a href="https://solscan.io/tx/{{.Signature}}" rel="noreferrer">Solscan'de doğrula ↗</a>{{end}}</article>{{else}}<p>Görünür işlem satırı yok.</p>{{end}}</div></details>

<section class="integrity"><div><span>Vaka referansı</span><code>{{.Case.CaseRef}}</code></div><div><span>Bundle hash</span><code>{{.Case.BundleHash}}</code></div><div><span>Ruleset</span><code>{{.Case.RulesetVersion}}</code></div><div><span>Üretim zamanı</span><b>{{.Case.ProducedAt.Format "02 Jan 2006 · 15:04 UTC"}}</b></div></section>
<section class="boundaries"><h2>Bu rapor ne iddia etmez?</h2><ul><li>Bu cüzdanın gerçek hayatta kime ait olduğunu söylemez.</li><li>Vanity adres benzerliği aynı sahip, aynı kişi veya ortak kontrol kanıtı değildir.</li><li>Possible-dust satırları funding veya aktör ilişkisi kanıtı değildir ve grade'e girmez.</li><li>Kötü niyet, dolandırıcılık veya suç isnadı yapmaz.</li><li>Eksik worker işlerini güvenli kabul etmez.</li><li>Yatırım tavsiyesi veya otomatik işlem onayı değildir.</li></ul><div class="buttons"><a href="/cases">Vaka listesine dön</a><a class="primary" href="{{.Case.TechnicalURL}}">Ham teknik dossier</a></div></section>
</main>
</body>
</html>`))
