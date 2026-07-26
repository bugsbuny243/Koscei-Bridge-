package handlers

import (
	"database/sql"
	"errors"
	"html/template"
	"net/http"
	"strings"
)

func (h *Handler) PublicContractFindingPage(w http.ResponseWriter, r *http.Request) {
	ref := strings.Trim(strings.TrimPrefix(r.URL.Path, "/contract-finding/"), "/")
	item, err := h.loadPublicContractFindingByRef(r.Context(), ref)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Contract finding evidence is temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=30, stale-while-revalidate=120")
	if err := publicContractFindingPageTemplate.Execute(w, item); err != nil {
		http.Error(w, "Contract finding page rendering failed", http.StatusInternalServerError)
	}
}

var publicContractFindingPageTemplate = template.Must(template.New("public-contract-finding").Parse(`<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="description" content="Koschei ARVIS owner tarafından yayınlanmış redakte akıllı kontrat güvenlik bulgusu.">
<meta name="theme-color" content="#02050a">
<title>Koschei ARVIS | Akıllı Kontrat Bulgusu</title>
<link rel="stylesheet" href="/css/koschei-soc.css?v=1">
<style>
.finding-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px}.finding-box{border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:16px;background:rgba(255,255,255,.025)}.finding-box span{display:block;color:#7f91a9;font-size:12px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:7px}.finding-box code{overflow-wrap:anywhere}.finding-boundary{margin-top:12px;padding:12px;border-left:3px solid #64748b;background:rgba(100,116,139,.08)}
</style>
</head>
<body class="soc-page">
<main class="soc-wrap">
<nav class="soc-nav"><a class="soc-brand" href="/live"><span class="soc-mark">K</span><span><strong>Koschei ARVIS</strong><small>Akıllı Kontrat Bulgusu</small></span></a><div class="soc-links"><a class="soc-btn" href="/live">Canlı SOC</a><a class="soc-btn" href="/security-radar">Radar</a></div></nav>
<header class="soc-hero"><span class="soc-kicker">{{.Severity}} · {{.Confidence}} · {{.LifecycleStatus}}</span><h1>{{.Title}}</h1><p>{{.Summary}}</p></header>
<section class="soc-panel"><div class="soc-panel-head"><div><span class="soc-kicker">REDakte DOĞRULANABİLİR KANIT</span><h2>{{.ProgramID}}</h2><p>{{.Network}} · Yayın {{.PublishedAt}}</p></div><span class="soc-tag">Verdict authority: false</span></div>
<div class="finding-grid">
<div class="finding-box"><span>Finding ref</span><code>{{.FindingRef}}</code></div><div class="finding-box"><span>Evidence hash</span><code>{{.EvidenceHash}}</code></div>
<div class="finding-box"><span>Kural</span><code>{{.RuleID}}</code></div><div class="finding-box"><span>Detector</span><code>{{.DetectorVersion}}</code></div>
<div class="finding-box"><span>Kaynak içerik hash'i</span><code>{{.SourceContentHash}}</code></div><div class="finding-box"><span>Kanıt durumu</span><code>{{.EvidenceStatus}}</code></div>
<div class="finding-box"><span>Önem</span><code>{{.Severity}}</code></div><div class="finding-box"><span>Güven / yaşam döngüsü</span><code>{{.Confidence}} / {{.LifecycleStatus}}</code></div>
<div class="finding-box"><span>Redaksiyon</span><code>{{.RedactionProfile}}</code></div><div class="finding-box"><span>Bulguyu oluşturma zamanı</span><code>{{.FindingCreatedAt}}</code></div>
</div></section>
<section class="soc-panel"><div class="soc-panel-head"><div><span class="soc-kicker">YAYIN SINIRI</span><h2>Bu bulgu neyi kanıtlamaz?</h2><p>Kaynak yolu, eşleşen kod parçası ve private artifact kimliği public projection içinde yer almaz.</p></div></div>{{range .Limitations}}<div class="finding-boundary">{{.}}</div>{{end}}</section>
<footer class="soc-footer"><span>© Koschei ARVIS · Önce kanıt</span><span>Statik bulgu exploit iddiası değildir.</span></footer>
</main>
</body>
</html>`))
