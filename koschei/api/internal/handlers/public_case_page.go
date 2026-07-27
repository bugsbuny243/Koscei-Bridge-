package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type publicCasePageData struct {
	CaseRef        string
	Title          string
	Summary        string
	Featured       bool
	PublishedAt    time.Time
	ProducedAt     time.Time
	BundleHash     string
	TargetKind     string
	TargetID       string
	TargetDisplay  string
	Network        string
	VerdictGrade   string
	VerdictStatus  string
	VerdictText    string
	RulesetVersion string
	Signature      string
	Acceptance     publicCaseAcceptanceView
	Metrics        []publicCaseMetricView
	Signals        []publicCaseSignalView
	Rules          []publicCaseRuleView
	DecisionPath   []string
	Funding        publicCaseFundingView
	Tokens         []publicCaseTokenView
	RelatedActors  []publicCaseActorView
	Evidence       []publicCaseEvidenceView
	Limitations    []string
	TechnicalURL   string
}

type publicCaseAcceptanceView struct {
	Status          string
	Class           string
	Pass            int
	Fail            int
	NotInvestigated int
	Hash            string
}

type publicCaseMetricView struct {
	Label string
	Value string
	Note  string
	Class string
}

type publicCaseSignalView struct {
	ID               string
	Label            string
	State            string
	StateClass       string
	AcceptanceStatus string
	Summary          string
	ReferenceCount   int
}

type publicCaseRuleView struct {
	ID       string
	Title    string
	State    string
	Class    string
	Summary  string
	Count    int
	Effect   string
}

type publicCaseFundingView struct {
	Available    bool
	Status       string
	Class        string
	Source       string
	Destination  string
	Amount       string
	ObservedAt   string
	Signature    string
	Slot         string
	Program      string
	Limitations  []string
}

type publicCaseTokenView struct {
	Mint         string
	Display      string
	Status       string
	Class        string
	FirstSeen    string
	LastSeen     string
	Roles        string
	Signature    string
}

type publicCaseActorView struct {
	Wallet        string
	Display       string
	Status        string
	Class         string
	SharedTokens  string
	MaxHolder     string
	FirstSeen     string
	LastSeen      string
	Limitation    string
}

type publicCaseEvidenceView struct {
	Relation      string
	RelationLabel string
	State         string
	Class         string
	Source        string
	Destination   string
	Amount        string
	Program       string
	ObservedAt    string
	Signature     string
	SignatureView string
	Slot          string
	Occurrences   int
}

// PublicCasePage renders a human-readable, evidence-bounded casefile. The
// immutable technical dossier remains available at /dossier/<case-ref> and is
// never mutated by this presentation layer.
func (h *Handler) PublicCasePage(w http.ResponseWriter, r *http.Request) {
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
	data := buildPublicCasePageData(bundle, title, summary, featured, publishedAt)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60, stale-while-revalidate=300")
	w.Header().Set("X-Robots-Tag", "index, follow")
	if err := publicCaseHTML.Execute(w, data); err != nil {
		http.Error(w, "public case render failed", http.StatusInternalServerError)
	}
}

func buildPublicCasePageData(bundle dossierBundle, title, summary string, featured bool, publishedAt time.Time) publicCasePageData {
	target := dossierMap(bundle.Target)
	verdict := dossierMap(bundle.Verdict)
	card := dossierMap(bundle.VerdictCard)
	acceptance := dossierMap(bundle.ActorAcceptance)
	connections := dossierMap(bundle.CrossTokenConnections)

	targetID := firstPublicDossierString(dossierString(target["id"]), dossierString(target["address"]), dossierString(target["mint"]))
	targetKind := firstPublicDossierString(dossierString(target["kind"]), "unknown")
	network := firstPublicDossierString(dossierString(target["network"]), dossierString(bundle.TechnicalReport["network"]), "solana-mainnet")
	if title == "" {
		title = defaultPublicDossierTitle(bundle)
	}
	if summary == "" {
		summary = defaultPublicDossierSummary(bundle)
	}

	data := publicCasePageData{
		CaseRef:        bundle.CaseRef,
		Title:          title,
		Summary:        summary,
		Featured:       featured,
		PublishedAt:    publishedAt.UTC(),
		ProducedAt:     bundle.ProducedAt.UTC(),
		BundleHash:     bundle.BundleHash,
		TargetKind:     targetKind,
		TargetID:       targetID,
		TargetDisplay:  maskPublicDossierTarget(targetID),
		Network:        network,
		VerdictGrade:   firstPublicDossierString(dossierString(verdict["grade"]), dossierString(verdict["letter_grade"]), "WITHHOLD"),
		VerdictStatus:  firstPublicDossierString(dossierString(verdict["verdict"]), dossierString(verdict["status"]), dossierString(verdict["decision"]), "evidence_bounded"),
		VerdictText:    publicCaseVerdictText(verdict),
		RulesetVersion: firstPublicDossierString(dossierString(verdict["ruleset_version"]), dossierString(verdict["actor_ruleset_version"]), dossierString(bundle.TechnicalReport["ruleset_version"])),
		Signature:      dossierString(verdict["signature"]),
		Acceptance: publicCaseAcceptanceView{
			Status:          firstPublicDossierString(dossierString(acceptance["status"]), "unknown"),
			Class:           publicCaseStateClass(dossierString(acceptance["status"])),
			Pass:            publicDossierInt(acceptance["pass_count"]),
			Fail:            publicDossierInt(acceptance["fail_count"]),
			NotInvestigated: publicDossierInt(acceptance["not_investigated_count"]),
			Hash:            dossierString(acceptance["acceptance_hash"]),
		},
		DecisionPath: publicCaseStrings(verdict["decision_path"]),
		Limitations:  append([]string(nil), bundle.Limitations...),
		TechnicalURL: "/dossier/" + bundle.CaseRef,
	}

	data.Signals = publicCaseSignals(card["signal_rows"])
	data.Rules = publicCaseRules(verdict["triggered_rules"])
	data.Funding = publicCaseFunding(bundle.FundingOrigin)
	data.Tokens = publicCaseTokens(bundle.CreatedTokenHistory)
	data.RelatedActors = publicCaseRelatedActors(connections["related_actor_observations"])
	data.Evidence = publicCaseEvidence(bundle.EvidenceLog, 36)
	data.Metrics = publicCaseMetrics(data, connections)
	return data
}

func publicCaseMetrics(data publicCasePageData, connections map[string]any) []publicCaseMetricView {
	verified, observed, inferred, unknown := 0, 0, 0, 0
	for _, row := range data.Signals {
		switch strings.ToLower(row.State) {
		case "verified":
			verified++
		case "observed":
			observed++
		case "inferred":
			inferred++
		default:
			unknown++
		}
	}
	counts := dossierMap(connections["counts"])
	return []publicCaseMetricView{
		{Label: "Evidence log", Value: strconv.Itoa(len(data.Evidence)), Note: "Son görünür kanıt satırları", Class: "cyan"},
		{Label: "Verified arms", Value: strconv.Itoa(verified), Note: "Doğrudan doğrulanmış", Class: "green"},
		{Label: "Observed arms", Value: strconv.Itoa(observed), Note: "Zincir üstü gözlem", Class: "cyan"},
		{Label: "Unknown / inferred", Value: strconv.Itoa(unknown + inferred), Note: "Güvenli sayılmaz", Class: "amber"},
		{Label: "Created tokens", Value: publicCaseNumber(firstPublicCaseValue(counts["created_tokens"], len(data.Tokens))), Note: "Vaka kapsamındaki token geçmişi", Class: "violet"},
		{Label: "Related actors", Value: publicCaseNumber(firstPublicCaseValue(counts["related_actors"], len(data.RelatedActors))), Note: "Kimlik veya ortak kontrol iddiası değildir", Class: "amber"},
	}
}

func publicCaseSignals(raw any) []publicCaseSignalView {
	items := dossierSlice(raw)
	out := make([]publicCaseSignalView, 0, len(items))
	for _, item := range items {
		row := dossierMap(item)
		refs := dossierMap(row["refs"])
		value := dossierMap(row["value"])
		state := firstPublicDossierString(dossierString(row["state"]), "unknown")
		out = append(out, publicCaseSignalView{
			ID:               dossierString(row["id"]),
			Label:            dossierString(row["label"]),
			State:            state,
			StateClass:       publicCaseStateClass(state),
			AcceptanceStatus: firstPublicDossierString(dossierString(row["acceptance_status"]), "not_investigated"),
			Summary:          dossierString(value["summary"]),
			ReferenceCount:   len(dossierSlice(refs["wallets"])) + len(dossierSlice(refs["accounts"])) + len(dossierSlice(refs["signatures"])) + len(dossierSlice(refs["evidence_keys"])),
		})
	}
	return out
}

func publicCaseRules(raw any) []publicCaseRuleView {
	items := dossierSlice(raw)
	out := make([]publicCaseRuleView, 0, len(items))
	for _, item := range items {
		rule := dossierMap(item)
		state := firstPublicDossierString(dossierString(rule["evidence_status"]), "unknown")
		out = append(out, publicCaseRuleView{
			ID:      dossierString(rule["rule_id"]),
			Title:   dossierString(rule["title"]),
			State:   state,
			Class:   publicCaseStateClass(state),
			Summary: dossierString(rule["summary"]),
			Count:   publicDossierInt(rule["count"]),
			Effect:  publicCaseHumanLabel(dossierString(rule["grade_effect"])),
		})
	}
	return out
}

func publicCaseFunding(raw any) publicCaseFundingView {
	funding := dossierMap(raw)
	if len(funding) == 0 {
		return publicCaseFundingView{}
	}
	status := firstPublicDossierString(dossierString(funding["verification_status"]), dossierString(funding["status"]), "unknown")
	amount := "—"
	if value := publicCaseFloat(funding["amount_sol"]); value != 0 {
		amount = strconv.FormatFloat(value, 'f', -1, 64) + " SOL"
	}
	return publicCaseFundingView{
		Available:   true,
		Status:      status,
		Class:       publicCaseStateClass(status),
		Source:      dossierString(funding["source_wallet"]),
		Destination: dossierString(funding["destination_wallet"]),
		Amount:      amount,
		ObservedAt:  publicCaseTimeText(funding["observed_at"]),
		Signature:   dossierString(funding["signature"]),
		Slot:        publicCaseNumber(funding["slot"]),
		Program:     dossierString(funding["program"]),
		Limitations: publicCaseStrings(funding["limitations"]),
	}
}

func publicCaseTokens(raw any) []publicCaseTokenView {
	items := dossierSlice(raw)
	if len(items) > 16 {
		items = items[:16]
	}
	out := make([]publicCaseTokenView, 0, len(items))
	for _, item := range items {
		token := dossierMap(item)
		mint := dossierString(token["mint"])
		status := firstPublicDossierString(dossierString(token["verification_status"]), "unknown")
		out = append(out, publicCaseTokenView{
			Mint:      mint,
			Display:   maskPublicDossierTarget(mint),
			Status:    status,
			Class:     publicCaseStateClass(status),
			FirstSeen: publicCaseTimeText(token["first_observed_at"]),
			LastSeen:  publicCaseTimeText(token["last_observed_at"]),
			Roles:     strings.Join(publicCaseStrings(token["roles"]), ", "),
			Signature: dossierString(token["creation_signature"]),
		})
	}
	return out
}

func publicCaseRelatedActors(raw any) []publicCaseActorView {
	items := dossierSlice(raw)
	if len(items) > 12 {
		items = items[:12]
	}
	out := make([]publicCaseActorView, 0, len(items))
	for _, item := range items {
		actor := dossierMap(item)
		wallet := dossierString(actor["wallet"])
		status := firstPublicDossierString(dossierString(actor["verification_status"]), "observed")
		maxHolder := "—"
		if value := publicCaseFloat(actor["max_holder_percentage"]); value != 0 {
			maxHolder = strconv.FormatFloat(value, 'f', 4, 64) + "%"
		}
		out = append(out, publicCaseActorView{
			Wallet:       wallet,
			Display:      maskPublicDossierTarget(wallet),
			Status:       status,
			Class:        publicCaseStateClass(status),
			SharedTokens: publicCaseNumber(actor["shared_token_count"]),
			MaxHolder:    maxHolder,
			FirstSeen:    publicCaseTimeText(actor["first_observed_at"]),
			LastSeen:     publicCaseTimeText(actor["last_observed_at"]),
			Limitation:   dossierString(actor["limitation"]),
		})
	}
	return out
}

func publicCaseEvidence(raw any, limit int) []publicCaseEvidenceView {
	items := dossierSlice(raw)
	type sortable struct {
		view publicCaseEvidenceView
		when time.Time
	}
	rows := make([]sortable, 0, len(items))
	for _, item := range items {
		row := dossierMap(item)
		state := firstPublicDossierString(dossierString(row["verification_status"]), "unknown")
		signature := dossierString(row["signature"])
		when := publicCaseTime(row["observed_at"])
		if when.IsZero() {
			when = publicCaseTime(row["timestamp"])
		}
		rows = append(rows, sortable{view: publicCaseEvidenceView{
			Relation:      dossierString(row["relation"]),
			RelationLabel: publicCaseHumanLabel(dossierString(row["relation"])),
			State:         state,
			Class:         publicCaseStateClass(state),
			Source:        firstPublicDossierString(dossierString(row["source_wallet"]), dossierString(row["actor_wallet"])),
			Destination:   firstPublicDossierString(dossierString(row["destination_wallet"]), dossierString(row["counterpart_id"]), dossierString(row["token_mint"])),
			Amount:        publicCaseEvidenceAmount(row),
			Program:       dossierString(row["program"]),
			ObservedAt:    publicCaseTimeText(when),
			Signature:     signature,
			SignatureView: maskPublicDossierTarget(signature),
			Slot:          publicCaseNumber(row["slot"]),
			Occurrences:   maxPublicCaseInt(1, publicDossierInt(row["occurrence_count"])),
		}, when: when})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].when.After(rows[j].when) })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	out := make([]publicCaseEvidenceView, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.view)
	}
	return out
}

func publicCaseEvidenceAmount(row map[string]any) string {
	amount := dossierMap(row["amount"])
	if token := publicCaseFloat(amount["token_amount"]); token != 0 {
		mint := dossierString(amount["token_mint"])
		return strconv.FormatFloat(token, 'f', -1, 64) + " " + maskPublicDossierTarget(mint)
	}
	if sol := publicCaseFloat(amount["native_sol"]); sol != 0 {
		return strconv.FormatFloat(sol, 'f', -1, 64) + " SOL"
	}
	if native := publicCaseFloat(row["amount_native"]); native != 0 {
		return strconv.FormatFloat(native, 'f', -1, 64) + " SOL"
	}
	return "—"
}

func publicCaseVerdictText(verdict map[string]any) string {
	if value := dossierString(verdict["verdict"]); value != "" {
		return publicCaseHumanLabel(value)
	}
	if path := publicCaseStrings(verdict["decision_path"]); len(path) > 0 {
		return path[len(path)-1]
	}
	return "Evidence-bounded deterministic result"
}

func publicCaseStateClass(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "verified", "pass", "passed", "complete", "completed", "success", "signed":
		return "verified"
	case "observed", "watch", "monitor":
		return "observed"
	case "inferred":
		return "inferred"
	case "failed", "fail", "critical", "high", "error":
		return "failed"
	default:
		return "unknown"
	}
}

func publicCaseHumanLabel(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "_", " "))
	if value == "" {
		return "Unknown"
	}
	words := strings.Fields(value)
	for index := range words {
		if len(words[index]) > 0 {
			words[index] = strings.ToUpper(words[index][:1]) + words[index][1:]
		}
	}
	return strings.Join(words, " ")
}

func publicCaseStrings(raw any) []string {
	items := dossierSlice(raw)
	out := make([]string, 0, len(items))
	for _, item := range items {
		value := strings.TrimSpace(publicCaseAnyString(item))
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func publicCaseAnyString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(typed), 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func publicCaseNumber(value any) string {
	text := strings.TrimSpace(publicCaseAnyString(value))
	if text == "" || text == "<nil>" {
		return "0"
	}
	return text
}

func publicCaseFloat(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case float32:
		return float64(typed)
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case json.Number:
		parsed, _ := typed.Float64()
		return parsed
	case string:
		parsed, _ := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return parsed
	default:
		return 0
	}
}

func publicCaseTime(value any) time.Time {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC()
	case string:
		parsed, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(typed))
		return parsed.UTC()
	default:
		return time.Time{}
	}
}

func publicCaseTimeText(value any) string {
	when := publicCaseTime(value)
	if when.IsZero() {
		return "—"
	}
	return when.Format("02 Jan 2006 · 15:04:05 UTC")
}

func firstPublicCaseValue(value any, fallback int) any {
	if strings.TrimSpace(publicCaseAnyString(value)) != "" && publicCaseAnyString(value) != "0" {
		return value
	}
	return fallback
}

func maxPublicCaseInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var publicCaseHTML = template.Must(template.New("public-case").Parse(`<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="description" content="Koschei ARVIS tarafından yayınlanan kanıt-temelli Solana güvenlik vakası.">
<meta name="theme-color" content="#02050a">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Koschei ARVIS">
<meta property="og:title" content="{{.Title}}">
<meta property="og:description" content="{{.Summary}}">
<meta property="og:url" content="https://tradepigloball.co/case/{{.CaseRef}}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{{.Title}}">
<meta name="twitter:description" content="{{.Summary}}">
<title>{{.Title}} · Koschei ARVIS</title>
<link rel="stylesheet" href="/css/public-casefile.css?v=1">
</head>
<body>
<main class="case-shell">
<nav class="case-nav">
<a class="brand" href="/"><span class="mark">K</span><span><strong>Koschei ARVIS</strong><small>Public Case Intelligence</small></span></a>
<div class="nav-actions"><a href="/live">Canlı SOC</a><a href="/cases">Tüm vakalar</a><a class="primary" href="{{.TechnicalURL}}">Ham teknik dossier</a></div>
</nav>

<header class="case-hero">
<div class="hero-copy">
<div class="eyebrow-row"><span class="eyebrow">{{.TargetKind}} investigation</span>{{if .Featured}}<span class="featured">FEATURED CASE</span>{{end}}</div>
<h1>{{.Title}}</h1>
<p>{{.Summary}}</p>
<div class="target-line"><span>Hedef</span><code>{{.TargetID}}</code></div>
<div class="hero-actions"><a class="button primary" href="#coverage">Kanıt kapsamını gör</a><a class="button" href="{{.TechnicalURL}}">Değişmez dosyayı doğrula</a></div>
</div>
<aside class="verdict-card">
<span class="verdict-label">Deterministic verdict</span>
<strong>{{.VerdictGrade}}</strong>
<b>{{.VerdictText}}</b>
<p>Ruleset: {{.RulesetVersion}}</p>
<div class="status-row"><span class="state {{.Acceptance.Class}}">{{.Acceptance.Status}}</span><span>{{.Acceptance.Pass}} pass · {{.Acceptance.Fail}} fail · {{.Acceptance.NotInvestigated}} unknown</span></div>
</aside>
</header>

<section class="proof-strip">
{{range .Metrics}}<article class="proof {{.Class}}"><span>{{.Label}}</span><strong>{{.Value}}</strong><small>{{.Note}}</small></article>{{end}}
</section>

<section class="panel executive">
<div class="panel-head"><div><span class="eyebrow">Executive finding</span><h2>Bu vaka ne söylüyor?</h2></div><span class="state {{.Acceptance.Class}}">{{.VerdictStatus}}</span></div>
<div class="decision-grid">
<div class="decision-path">{{range .DecisionPath}}<p>{{.}}</p>{{else}}<p>Deterministik karar yolu bu bundle içinde sunulmadı.</p>{{end}}</div>
<div class="integrity-box"><span>Case ref</span><code>{{.CaseRef}}</code><span>Bundle hash</span><code>{{.BundleHash}}</code><span>Verdict signature</span><code>{{.Signature}}</code><span>Produced</span><b>{{.ProducedAt.Format "02 Jan 2006 · 15:04 UTC"}}</b></div>
</div>
</section>

<section class="panel" id="coverage">
<div class="panel-head"><div><span class="eyebrow">ARVIS evidence coverage</span><h2>Kanıt kolları</h2><p>UNKNOWN güvenli anlamına gelmez; yalnız kanıt kapsamının tamamlanmadığını gösterir.</p></div><span class="count">{{len .Signals}} arm</span></div>
<div class="coverage-grid">{{range .Signals}}<article class="coverage {{.StateClass}}"><div><span>{{.ID}}</span><b>{{.Label}}</b></div><em>{{.State}}</em><p>{{.Summary}}</p><small>{{.ReferenceCount}} evidence reference · {{.AcceptanceStatus}}</small></article>{{else}}<div class="empty">Kanıt kapsam matrisi bulunamadı.</div>{{end}}</div>
</section>

{{if .Rules}}<section class="panel"><div class="panel-head"><div><span class="eyebrow">Triggered deterministic rules</span><h2>Grade’i etkileyen kurallar</h2></div><span class="count">{{len .Rules}} rule</span></div><div class="rule-list">{{range .Rules}}<article class="rule"><span class="state {{.Class}}">{{.State}}</span><div><code>{{.ID}}</code><h3>{{.Title}}</h3><p>{{.Summary}}</p><small>{{.Count}} observation · {{.Effect}}</small></div></article>{{end}}</div></section>{{end}}

<section class="split-grid">
<article class="panel funding"><div class="panel-head"><div><span class="eyebrow">Funding origin</span><h2>İlk fonlama izi</h2></div>{{if .Funding.Available}}<span class="state {{.Funding.Class}}">{{.Funding.Status}}</span>{{end}}</div>{{if .Funding.Available}}<div class="flow"><div><span>Kaynak</span><code>{{.Funding.Source}}</code></div><i>→</i><div><span>Hedef</span><code>{{.Funding.Destination}}</code></div></div><div class="fact-grid"><div><span>Miktar</span><b>{{.Funding.Amount}}</b></div><div><span>Zaman</span><b>{{.Funding.ObservedAt}}</b></div><div><span>Program</span><code>{{.Funding.Program}}</code></div><div><span>Slot</span><code>{{.Funding.Slot}}</code></div></div>{{if .Funding.Signature}}<a class="evidence-link" href="https://solscan.io/tx/{{.Funding.Signature}}" rel="noreferrer">İşlemi Solscan’de aç ↗</a>{{end}}{{range .Funding.Limitations}}<p class="limitation">{{.}}</p>{{end}}{{else}}<div class="empty">Bu bundle içinde doğrulanabilir funding origin bulunmadı.</div>{{end}}</article>

<article class="panel"><div class="panel-head"><div><span class="eyebrow">Actor recurrence</span><h2>Bağlantılı aktör gözlemleri</h2></div><span class="count">{{len .RelatedActors}}</span></div>{{if .RelatedActors}}<div class="actor-list">{{range .RelatedActors}}<article><div><b>{{.Display}}</b><code>{{.Wallet}}</code></div><span class="state {{.Class}}">{{.Status}}</span><dl><div><dt>Shared token</dt><dd>{{.SharedTokens}}</dd></div><div><dt>Max holder</dt><dd>{{.MaxHolder}}</dd></div><div><dt>İlk / son</dt><dd>{{.FirstSeen}}<br>{{.LastSeen}}</dd></div></dl><p>{{.Limitation}}</p></article>{{end}}</div>{{else}}<div class="empty">Tekrar eden related-actor gözlemi yok.</div>{{end}}</article>
</section>

<section class="panel"><div class="panel-head"><div><span class="eyebrow">Created-token history</span><h2>Aktörün token yüzeyi</h2></div><span class="count">{{len .Tokens}} token</span></div>{{if .Tokens}}<div class="token-grid">{{range .Tokens}}<article><div><span class="state {{.Class}}">{{.Status}}</span><b>{{.Display}}</b></div><code>{{.Mint}}</code><dl><div><dt>Rol</dt><dd>{{.Roles}}</dd></div><div><dt>İlk görüldü</dt><dd>{{.FirstSeen}}</dd></div><div><dt>Son görüldü</dt><dd>{{.LastSeen}}</dd></div></dl>{{if .Signature}}<a href="https://solscan.io/tx/{{.Signature}}" rel="noreferrer">Creation evidence ↗</a>{{end}}</article>{{end}}</div>{{else}}<div class="empty">Bu vaka içinde created-token geçmişi yok.</div>{{end}}</section>

<section class="panel evidence-panel"><div class="panel-head"><div><span class="eyebrow">Evidence timeline</span><h2>Doğrulanabilir işlem satırları</h2><p>Ham bundle’ın tamamı teknik dossier içinde korunur. Burada son ve en anlamlı zincir üstü satırlar gösterilir.</p></div><span class="count">{{len .Evidence}} visible</span></div>{{if .Evidence}}<div class="evidence-table-wrap"><table><thead><tr><th>Zaman / durum</th><th>İlişki</th><th>Kaynak → hedef</th><th>Miktar</th><th>Program / slot</th><th>İşlem</th></tr></thead><tbody>{{range .Evidence}}<tr><td><span class="state {{.Class}}">{{.State}}</span><small>{{.ObservedAt}}</small></td><td><b>{{.RelationLabel}}</b><small>{{.Occurrences}} occurrence</small></td><td><code>{{.Source}}</code><i>→</i><code>{{.Destination}}</code></td><td>{{.Amount}}</td><td><code>{{.Program}}</code><small>slot {{.Slot}}</small></td><td>{{if .Signature}}<a href="https://solscan.io/tx/{{.Signature}}" rel="noreferrer">{{.SignatureView}} ↗</a>{{else}}—{{end}}</td></tr>{{end}}</tbody></table></div>{{else}}<div class="empty">Görünür evidence satırı bulunamadı.</div>{{end}}</section>

<section class="panel boundary"><div><span class="eyebrow">Evidence boundaries</span><h2>Bu rapor neyi iddia etmez?</h2></div><div>{{range .Limitations}}<p>{{.}}</p>{{end}}</div></section>

<footer><div><b>Koschei ARVIS</b><span>Verify, record, then trust by policy.</span></div><div><span>Published {{.PublishedAt.Format "02 Jan 2006 · 15:04 UTC"}}</span><a href="{{.TechnicalURL}}">Raw immutable dossier</a></div></footer>
</main>
</body>
</html>`))
