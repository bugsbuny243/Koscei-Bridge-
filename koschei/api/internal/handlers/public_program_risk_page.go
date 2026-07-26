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
	"label": publicProgramRiskLabel,
}).Parse(`<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="description" content="Koschei ARVIS doğrulanabilir Solana akıllı kontrat ve program tehlike kaydı.">
<meta name="theme-color" content="#02050a">
<title>{{.Title}} · Koschei ARVIS</title>
<link rel="stylesheet" href="/css/koschei-soc.css?v=1">
<style>
.risk-shell{width:min(1080px,100%);margin:auto;padding:12px 12px 70px}.risk-hero,.risk-panel{border:1px solid #163040;border-radius:24px;background:linear-gradient(160deg,rgba(10,27,39,.98),rgba(4,14,22,.98));padding:24px;margin:16px 0}.risk-hero{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(240px,.6fr);gap:18px}.risk-hero h1{font-size:clamp(34px,7vw,64px);line-height:1;margin:10px 0}.risk-kicker{color:#4ce6c2;font:700 11px ui-monospace,monospace;letter-spacing:.12em}.risk-decision{border:1px solid #28495b;border-radius:18px;padding:20px;display:flex;flex-direction:column;gap:10px;overflow:hidden}.risk-decision strong{font-size:clamp(30px,8vw,58px);line-height:1;overflow-wrap:normal;word-break:normal}.risk-decision.critical strong{color:#ff7c8f}.risk-decision.high strong{color:#ffc767}.risk-action{font-size:18px;color:#e8f6f7}.risk-tags{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.risk-tag{padding:7px 10px;border:1px solid #285064;border-radius:999px;font:700 11px ui-monospace,monospace}.risk-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.risk-box{border:1px solid #143041;border-radius:15px;padding:14px;background:#07121b}.risk-box span{display:block;color:#8ea5ad;font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}.risk-box code{overflow-wrap:anywhere}.risk-list{display:grid;gap:10px}.risk-list div{padding:13px;border-left:3px solid #58d5ef;background:#0b202b}.risk-links{display:flex;gap:9px;flex-wrap:wrap}.risk-links a{padding:10px 14px;border:1px solid #285064;border-radius:999px;color:#ecf7f8;text-decoration:none;font-weight:700}.risk-links a.primary{background:#4ce6c2;color:#01211c;border:0}@media(max-width:720px){.risk-hero,.risk-grid{grid-template-columns:1fr}.risk-shell{padding-left:8px;padding-right:8px}.risk-hero,.risk-panel{padding:18px}.risk-decision strong{font-size:42px;white-space:normal}.risk-box code{font-size:11px}}
</style>
</head>
<body class="soc-page">
<main class="risk-shell">
<nav class="soc-nav"><a class="soc-brand" href="/live"><span class="soc-mark">K</span><span><strong>Koschei ARVIS</strong><small>Program Güvenlik Radarı</small></span></a><div class="soc-links"><a class="soc-btn" href="/live">Canlı SOC</a><a class="soc-btn" href="/security-radar">Tarama</a></div></nav>
<header class="risk-hero"><div><span class="risk-kicker">{{.Severity}} · {{.LifecycleStatus}} · ZİNCİR ÜSTÜ KANIT</span><h1>{{.Title}}</h1><p>{{.Summary}}</p><div class="risk-tags">{{range .RiskTypes}}<span class="risk-tag">{{label .}}</span>{{end}}</div></div><aside class="risk-decision {{.Severity}}"><span class="risk-kicker">ARVIS KARARI</span><strong>{{.Decision}}</strong><p class="risk-action">{{.RecommendedAction}}</p></aside></header>
<section class="risk-panel"><span class="risk-kicker">NEYİ KANITLADIK?</span><h2>Doğrulanmış teknik durum</h2><div class="risk-grid"><div class="risk-box"><span>Program</span><code>{{.ProgramID}}</code></div><div class="risk-box"><span>Ağ</span><b>{{.Network}}</b></div><div class="risk-box"><span>Kanıt referansı</span><code>{{.EventRef}}</code></div><div class="risk-box"><span>Doğrulama hash'i</span><code>{{.VerificationHash}}</code></div><div class="risk-box"><span>Güncel binary hash</span><code>{{show .CurrentBinaryHash}}</code></div><div class="risk-box"><span>Upgrade authority</span><code>{{show .CurrentUpgradeAuthority}}</code></div><div class="risk-box"><span>Loader</span><code>{{show .CurrentLoaderKind}}</code></div><div class="risk-box"><span>Kaynak eşleşmesi</span><code>{{show .CurrentSourceMatch}}</code></div></div></section>
{{if .PreviousSnapshotRef}}<section class="risk-panel"><span class="risk-kicker">NE DEĞİŞTİ?</span><h2>Önceki ve güncel dağıtım</h2><div class="risk-grid"><div class="risk-box"><span>Önceki snapshot</span><code>{{.PreviousSnapshotRef}}</code></div><div class="risk-box"><span>Güncel snapshot</span><code>{{.CurrentSnapshotRef}}</code></div><div class="risk-box"><span>Önceki binary</span><code>{{show .PreviousBinaryHash}}</code></div><div class="risk-box"><span>Güncel binary</span><code>{{show .CurrentBinaryHash}}</code></div></div></section>{{end}}
<section class="risk-panel"><span class="risk-kicker">BAĞIMSIZ DOĞRULAMA</span><h2>Yayınlanan veri yeniden hash'lenebilir</h2><p>API yanıtındaki <code>verification_payload</code> alanını UTF-8 JSON olarak hash'leyerek <code>{{.VerificationHash}}</code> değerini yeniden üretebilirsin.</p><div class="risk-links"><a class="primary" href="/api/public/program-risks/{{.EventRef}}">JSON kanıtını aç</a><a href="https://solscan.io/account/{{.ProgramID}}" rel="noreferrer">Solscan'de programı aç ↗</a></div></section>
<section class="risk-panel"><span class="risk-kicker">SINIR</span><h2>Bu kayıt neyi iddia etmez?</h2><div class="risk-list">{{range .Limitations}}<div>{{.}}</div>{{end}}</div></section>
</main>
</body>
</html>`))

func publicProgramRiskLabel(value string) string {
	switch value {
	case "loader_changed":
		return "Program loader değişti"
	case "programdata_address_changed":
		return "ProgramData adresi değişti"
	case "bytecode_changed":
		return "Program bytecode değişti"
	case "upgrade_authority_opened":
		return "Upgrade authority açıldı"
	case "upgrade_authority_changed":
		return "Upgrade authority değişti"
	case "program_not_executable":
		return "Program executable değil"
	case "source_binary_mismatch":
		return "Kaynak ve bytecode uyuşmuyor"
	case "upgrade_authority_open":
		return "Upgrade authority açık"
	default:
		return value
	}
}
