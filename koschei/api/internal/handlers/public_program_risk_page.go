package handlers

import (
	"database/sql"
	"errors"
	"html/template"
	"net/http"
	"strings"
)

func (h *Handler) PublicProgramRiskPage(w http.ResponseWriter, r *http.Request) {
	ref := strings.Trim(strings.TrimPrefix(r.URL.Path, "/program-risk/"), "/")
	item, err := h.loadPublicProgramRiskByRef(r.Context(), ref)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Program risk evidence is temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=30, stale-while-revalidate=120")
	if err := publicProgramRiskPageTemplate.Execute(w, item); err != nil {
		http.Error(w, "Program risk page rendering failed", http.StatusInternalServerError)
	}
}

var publicProgramRiskPageTemplate = template.Must(template.New("public-program-risk").Funcs(template.FuncMap{
	"show": func(value string) string {
		if strings.TrimSpace(value) == "" {
			return "—"
		}
		return value
	},
}).Parse(`<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="description" content="Koschei ARVIS doğrulanmış Solana program risk kanıtı.">
<meta name="theme-color" content="#02050a">
<title>Koschei ARVIS | Program Risk Kanıtı</title>
<link rel="stylesheet" href="/css/koschei-soc.css?v=1">
<style>
.risk-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}.risk-box{border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:16px;background:rgba(255,255,255,.025)}.risk-box span{display:block;color:#7f91a9;font-size:12px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:7px}.risk-box b,.risk-box code{overflow-wrap:anywhere}.risk-types{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}.risk-boundary{margin-top:12px;padding:12px;border-left:3px solid #64748b;background:rgba(100,116,139,.08)}
</style>
</head>
<body class="soc-page">
<main class="soc-wrap">
<nav class="soc-nav"><a class="soc-brand" href="/live"><span class="soc-mark">K</span><span><strong>Koschei ARVIS</strong><small>Program Risk Kanıtı</small></span></a><div class="soc-links"><a class="soc-btn" href="/live">Canlı SOC</a><a class="soc-btn" href="/security-radar">Radar</a></div></nav>
<header class="soc-hero"><span class="soc-kicker">{{.Severity}} · {{.EvidenceStatus}}</span><h1>{{if eq .Type "program_deployment_changed"}}Program dağıtımı değişti{{else}}Program kontrol riski{{end}}</h1><p>{{.Summary}}</p><div class="risk-types">{{range .RiskTypes}}<span class="soc-tag">{{.}}</span>{{end}}</div></header>
<section class="soc-panel"><div class="soc-panel-head"><div><span class="soc-kicker">DOĞRULANABİLİR KANIT</span><h2>{{.ProgramID}}</h2><p>{{.Network}} · {{.OccurredAt}}</p></div><span class="soc-tag">Verdict authority: false</span></div>
<div class="risk-grid">
<div class="risk-box"><span>Kanıt referansı</span><code>{{.EventRef}}</code></div><div class="risk-box"><span>Kanıt hash'i</span><code>{{.EvidenceHash}}</code></div>
<div class="risk-box"><span>Önceki snapshot</span><code>{{show .PreviousSnapshotRef}}</code></div><div class="risk-box"><span>Güncel snapshot</span><code>{{show .CurrentSnapshotRef}}</code></div>
<div class="risk-box"><span>Önceki binary hash</span><code>{{show .PreviousBinaryHash}}</code></div><div class="risk-box"><span>Güncel binary hash</span><code>{{show .CurrentBinaryHash}}</code></div>
<div class="risk-box"><span>Upgrade authority önce</span><code>{{show .PreviousUpgradeAuthority}}</code></div><div class="risk-box"><span>Upgrade authority şimdi</span><code>{{show .CurrentUpgradeAuthority}}</code></div>
<div class="risk-box"><span>Loader önce</span><code>{{show .PreviousLoaderKind}}</code></div><div class="risk-box"><span>Loader şimdi</span><code>{{show .CurrentLoaderKind}}</code></div>
<div class="risk-box"><span>ProgramData önce</span><code>{{show .PreviousProgramDataAddress}}</code></div><div class="risk-box"><span>ProgramData şimdi</span><code>{{show .CurrentProgramDataAddress}}</code></div>
<div class="risk-box"><span>Kaynak eşleşmesi önce</span><code>{{show .PreviousSourceMatch}}</code></div><div class="risk-box"><span>Kaynak eşleşmesi şimdi</span><code>{{show .CurrentSourceMatch}}</code></div>
</div></section>
<section class="soc-panel"><div class="soc-panel-head"><div><span class="soc-kicker">YAYIN SINIRI</span><h2>Bu alarm neyi kanıtlamaz?</h2></div></div>{{range .Limitations}}<div class="risk-boundary">{{.}}</div>{{end}}</section>
<footer class="soc-footer"><span>© Koschei ARVIS · Önce kanıt</span><span>Kimlik veya niyet isnadı yok.</span></footer>
</main>
</body>
</html>`))
