package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

var publicProgramRiskRefPattern = regexp.MustCompile(`^(KDCE1|KDS1)-[0-9a-f]{32}$`)

type publicProgramRisk struct {
	Type                       string    `json:"type"`
	EventRef                   string    `json:"event_ref"`
	PublicURL                  string    `json:"public_url"`
	ProgramID                  string    `json:"program_id"`
	Network                    string    `json:"network"`
	Severity                   string    `json:"severity"`
	RiskTypes                  []string  `json:"risk_types"`
	Summary                    string    `json:"summary"`
	EvidenceRows               int       `json:"evidence_rows"`
	EvidenceHash               string    `json:"evidence_hash"`
	PreviousSnapshotRef        string    `json:"previous_snapshot_ref,omitempty"`
	CurrentSnapshotRef         string    `json:"current_snapshot_ref"`
	PreviousBinaryHash         string    `json:"previous_binary_hash,omitempty"`
	CurrentBinaryHash          string    `json:"current_binary_hash"`
	PreviousUpgradeAuthority   string    `json:"previous_upgrade_authority,omitempty"`
	CurrentUpgradeAuthority    string    `json:"current_upgrade_authority,omitempty"`
	PreviousSourceMatch        string    `json:"previous_source_match,omitempty"`
	CurrentSourceMatch         string    `json:"current_source_match"`
	PreviousLoaderKind         string    `json:"previous_loader_kind,omitempty"`
	CurrentLoaderKind          string    `json:"current_loader_kind"`
	PreviousProgramDataAddress string    `json:"previous_programdata_address,omitempty"`
	CurrentProgramDataAddress  string    `json:"current_programdata_address,omitempty"`
	OccurredAt                 time.Time `json:"occurred_at"`
	VerdictAuthority           bool      `json:"verdict_authority"`
	EvidenceStatus             string    `json:"evidence_status"`
	Limitations                []string  `json:"limitations"`
}

type publicUnifiedSOCEvent struct {
	Type        string    `json:"type"`
	IdentityKey string    `json:"identity_key"`
	EventRef    string    `json:"event_ref,omitempty"`
	CaseRef     string    `json:"case_ref,omitempty"`
	Title       string    `json:"title"`
	TargetKind  string    `json:"target_kind"`
	Target      string    `json:"target"`
	Verdict     string    `json:"verdict,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	ChangeTypes []string  `json:"change_types,omitempty"`
	Evidence    int       `json:"evidence_rows"`
	OccurredAt  time.Time `json:"occurred_at"`
	PublicURL   string    `json:"public_url"`
	BundleHash  string    `json:"bundle_hash,omitempty"`
	EventHash   string    `json:"event_hash,omitempty"`
	Verifiable  bool      `json:"verifiable"`
	Description string    `json:"description"`
}

type publicProgramRiskScanner interface {
	Scan(dest ...any) error
}

const publicProgramChangeQuery = `
	SELECT e.event_ref,e.program_id,e.network,e.change_types,e.severity,e.summary,e.event_hash,e.created_at,
	       e.previous_snapshot_ref,e.current_snapshot_ref,
	       p.canonical_binary_hash,c.canonical_binary_hash,
	       COALESCE(p.upgrade_authority,''),COALESCE(c.upgrade_authority,''),
	       p.match_status,c.match_status,p.loader_kind,c.loader_kind,
	       COALESCE(p.programdata_address,''),COALESCE(c.programdata_address,'')
	FROM defense_program_change_events e
	JOIN defense_program_deployments p ON p.snapshot_ref=e.previous_snapshot_ref
	JOIN defense_program_deployments c ON c.snapshot_ref=e.current_snapshot_ref
	WHERE e.severity IN ('high','critical')`

const publicProgramSnapshotQuery = `
	SELECT snapshot_ref,program_id,network,loader_kind,COALESCE(programdata_address,''),
	       COALESCE(upgrade_authority,''),upgrade_authority_open,executable,canonical_binary_hash,
	       match_status,snapshot_hash,created_at
	FROM defense_program_deployments`

func (h *Handler) PublicUnifiedSOCFeed(w http.ResponseWriter, r *http.Request) {
	cases, err := h.loadPublicDossierCases(r, 40)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "status": "unavailable", "events": []publicUnifiedSOCEvent{},
		})
		return
	}
	risks, err := h.loadPublicProgramRisks(r.Context(), 40)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "status": "unavailable", "events": []publicUnifiedSOCEvent{},
		})
		return
	}

	actorCases, tokenCases, verified, observed, featured := 0, 0, 0, 0, 0
	criticalPrograms, highPrograms := 0, 0
	events := make([]publicUnifiedSOCEvent, 0, len(cases)+len(risks))
	seenTargets := map[string]struct{}{}
	publishedCases := 0
	for _, item := range cases {
		key := strings.ToLower(strings.TrimSpace(item.TargetKind)) + ":" + strings.TrimSpace(item.TargetID)
		if key == ":" {
			key = "case:" + item.CaseRef
		}
		if _, exists := seenTargets[key]; exists {
			continue
		}
		seenTargets[key] = struct{}{}
		publishedCases++
		switch strings.ToLower(item.TargetKind) {
		case "wallet":
			actorCases++
		case "token_mint", "token":
			tokenCases++
		}
		verified += item.VerifiedRows
		observed += item.ObservedRows
		if item.Featured {
			featured++
		}
		verdict := firstPublicDossierString(item.VerdictGrade, item.VerdictStatus)
		events = append(events, publicUnifiedSOCEvent{
			Type: "immutable_case_published", IdentityKey: key, CaseRef: item.CaseRef, Title: item.Title,
			TargetKind: item.TargetKind, Target: item.TargetDisplay, Verdict: verdict,
			Evidence: item.EvidenceRows, OccurredAt: item.PublishedAt, PublicURL: item.PublicURL,
			BundleHash: item.BundleHash, Verifiable: item.BundleHash != "",
			Description: "Açıkça yayınlanmış değişmez ARVIS kanıt vakası.",
		})
	}
	for _, item := range risks {
		if item.Severity == "critical" {
			criticalPrograms++
		} else if item.Severity == "high" {
			highPrograms++
		}
		events = append(events, publicUnifiedSOCEvent{
			Type: item.Type, IdentityKey: item.EventRef, EventRef: item.EventRef,
			Title: publicProgramRiskTitle(item), TargetKind: "solana_program", Target: item.ProgramID,
			Severity: item.Severity, ChangeTypes: append([]string(nil), item.RiskTypes...),
			Evidence: item.EvidenceRows, OccurredAt: item.OccurredAt, PublicURL: item.PublicURL,
			EventHash: item.EvidenceHash, Verifiable: item.EvidenceHash != "", Description: item.Summary,
		})
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].OccurredAt.After(events[j].OccurredAt) })
	if len(events) > 50 {
		events = events[:50]
	}
	var lastPublished any
	if len(events) > 0 {
		lastPublished = events[0].OccurredAt
	}
	w.Header().Set("Cache-Control", "public, max-age=10, stale-while-revalidate=30")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"status": "operational",
		"generated_at": time.Now().UTC(),
		"refresh_seconds": 15,
		"summary": map[string]any{
			"published_cases": publishedCases, "featured_cases": featured,
			"actor_cases": actorCases, "token_cases": tokenCases,
			"program_risk_events": len(risks), "critical_program_events": criticalPrograms,
			"high_program_events": highPrograms,
			"verified_evidence_rows": verified, "observed_evidence_rows": observed,
			"last_published_at": lastPublished,
		},
		"events": events,
		"boundaries": []string{
			"Özel müşteri taramaları ve iç worker ayrıntıları yayımlanmaz.",
			"Program alarmı yalnızca değişmez snapshot/event hash'i bulunan HIGH veya CRITICAL zincir üstü teknik durumdan üretilir.",
			"Açık upgrade authority teknik kontrol riski demektir; tek başına kötü niyet, saldırı veya dolandırıcılık iddiası değildir.",
			"Kaynak doğrulanmamışsa uyuşmazlık varmış gibi gösterilmez; yalnızca açıkça doğrulanan manifest-bytecode çelişkisi yayımlanır.",
		},
	})
}

func (h *Handler) PublicProgramRisks(w http.ResponseWriter, r *http.Request) {
	limit := publicDossierLimit(r.URL.Query().Get("limit"), 24, 100)
	items, err := h.loadPublicProgramRisks(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "error": "public_program_risks_unavailable", "risks": []publicProgramRisk{},
		})
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=15, stale-while-revalidate=60")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"generated_at": time.Now().UTC(),
		"count": len(items),
		"risks": items,
		"publication_policy": map[string]any{
			"onchain_state_only": true,
			"minimum_severity": "high",
			"verdict_authority": false,
			"identity_or_wrongdoing_claim": false,
		},
	})
}

func (h *Handler) PublicProgramRiskItem(w http.ResponseWriter, r *http.Request) {
	ref := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/public/program-risks/"), "/")
	item, err := h.loadPublicProgramRiskByRef(r.Context(), ref)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "program_risk_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "program_risk_unavailable"})
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=30, stale-while-revalidate=120")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "risk": item})
}

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

func (h *Handler) loadPublicProgramRisks(ctx context.Context, limit int) ([]publicProgramRisk, error) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	if limit <= 0 || limit > 100 {
		limit = 24
	}

	items := make([]publicProgramRisk, 0, limit*2)
	representedSnapshots := map[string]struct{}{}
	changeRows, err := db.QueryContext(ctx, publicProgramChangeQuery+` ORDER BY e.created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	for changeRows.Next() {
		item, scanErr := scanPublicProgramChange(changeRows)
		if scanErr != nil {
			changeRows.Close()
			return nil, scanErr
		}
		representedSnapshots[item.CurrentSnapshotRef] = struct{}{}
		items = append(items, item)
	}
	if err := changeRows.Err(); err != nil {
		changeRows.Close()
		return nil, err
	}
	changeRows.Close()

	snapshotRows, err := db.QueryContext(ctx, `WITH latest AS (
		SELECT DISTINCT ON (program_id,network)
		       snapshot_ref,program_id,network,loader_kind,programdata_address,upgrade_authority,
		       upgrade_authority_open,executable,canonical_binary_hash,match_status,snapshot_hash,created_at
		FROM defense_program_deployments
		ORDER BY program_id,network,created_at DESC
	) `+publicProgramSnapshotQuery+` FROM latest
	WHERE upgrade_authority_open=true OR match_status='mismatched' OR executable=false
	ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	for snapshotRows.Next() {
		item, scanErr := scanPublicProgramSnapshot(snapshotRows)
		if scanErr != nil {
			snapshotRows.Close()
			return nil, scanErr
		}
		if _, represented := representedSnapshots[item.CurrentSnapshotRef]; represented {
			continue
		}
		items = append(items, item)
	}
	if err := snapshotRows.Err(); err != nil {
		snapshotRows.Close()
		return nil, err
	}
	snapshotRows.Close()

	sort.SliceStable(items, func(i, j int) bool { return items[i].OccurredAt.After(items[j].OccurredAt) })
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (h *Handler) loadPublicProgramRiskByRef(ctx context.Context, ref string) (publicProgramRisk, error) {
	ref = strings.TrimSpace(ref)
	if !publicProgramRiskRefPattern.MatchString(ref) {
		return publicProgramRisk{}, sql.ErrNoRows
	}
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return publicProgramRisk{}, errors.New("database unavailable")
	}
	if strings.HasPrefix(ref, "KDCE1-") {
		return scanPublicProgramChange(db.QueryRowContext(ctx, publicProgramChangeQuery+` AND e.event_ref=$1`, ref))
	}
	return scanPublicProgramSnapshot(db.QueryRowContext(ctx, publicProgramSnapshotQuery+`
		WHERE snapshot_ref=$1 AND (upgrade_authority_open=true OR match_status='mismatched' OR executable=false)`, ref))
}

func scanPublicProgramChange(row publicProgramRiskScanner) (publicProgramRisk, error) {
	var item publicProgramRisk
	var typesRaw []byte
	err := row.Scan(
		&item.EventRef, &item.ProgramID, &item.Network, &typesRaw, &item.Severity, &item.Summary,
		&item.EvidenceHash, &item.OccurredAt, &item.PreviousSnapshotRef, &item.CurrentSnapshotRef,
		&item.PreviousBinaryHash, &item.CurrentBinaryHash, &item.PreviousUpgradeAuthority,
		&item.CurrentUpgradeAuthority, &item.PreviousSourceMatch, &item.CurrentSourceMatch,
		&item.PreviousLoaderKind, &item.CurrentLoaderKind, &item.PreviousProgramDataAddress,
		&item.CurrentProgramDataAddress,
	)
	if err != nil {
		return publicProgramRisk{}, err
	}
	_ = json.Unmarshal(typesRaw, &item.RiskTypes)
	item.Type = "program_deployment_changed"
	item.PublicURL = "/program-risk/" + item.EventRef
	item.EvidenceRows = len(item.RiskTypes) + 2
	item.EvidenceStatus = "verified_onchain_state_transition"
	item.VerdictAuthority = false
	item.Limitations = publicProgramRiskLimitations()
	return item, nil
}

func scanPublicProgramSnapshot(row publicProgramRiskScanner) (publicProgramRisk, error) {
	var item publicProgramRisk
	var authorityOpen, executable bool
	err := row.Scan(
		&item.EventRef, &item.ProgramID, &item.Network, &item.CurrentLoaderKind,
		&item.CurrentProgramDataAddress, &item.CurrentUpgradeAuthority, &authorityOpen, &executable,
		&item.CurrentBinaryHash, &item.CurrentSourceMatch, &item.EvidenceHash, &item.OccurredAt,
	)
	if err != nil {
		return publicProgramRisk{}, err
	}
	item.RiskTypes = publicProgramSnapshotRiskTypes(authorityOpen, executable, item.CurrentSourceMatch)
	if len(item.RiskTypes) == 0 {
		return publicProgramRisk{}, sql.ErrNoRows
	}
	item.Type = "program_control_risk_observed"
	item.CurrentSnapshotRef = item.EventRef
	item.PublicURL = "/program-risk/" + item.EventRef
	item.Severity = publicProgramSnapshotRiskSeverity(item.RiskTypes)
	item.Summary = publicProgramSnapshotRiskSummary(item.RiskTypes)
	item.EvidenceRows = len(item.RiskTypes) + 1
	item.EvidenceStatus = "verified_onchain_program_state"
	item.VerdictAuthority = false
	item.Limitations = publicProgramRiskLimitations()
	return item, nil
}

func publicProgramSnapshotRiskTypes(authorityOpen, executable bool, matchStatus string) []string {
	out := []string{}
	if !executable {
		out = append(out, "program_not_executable")
	}
	if strings.EqualFold(strings.TrimSpace(matchStatus), "mismatched") {
		out = append(out, "source_binary_mismatch")
	}
	if authorityOpen {
		out = append(out, "upgrade_authority_open")
	}
	return out
}

func publicProgramSnapshotRiskSeverity(types []string) string {
	for _, value := range types {
		if value == "program_not_executable" || value == "source_binary_mismatch" {
			return "critical"
		}
	}
	return "high"
}

func publicProgramSnapshotRiskSummary(types []string) string {
	has := func(want string) bool {
		for _, value := range types {
			if value == want {
				return true
			}
		}
		return false
	}
	switch {
	case has("source_binary_mismatch") && has("upgrade_authority_open"):
		return "Dağıtılmış program bytecode'u sağlanan kaynak manifestiyle doğrulanmış biçimde uyuşmuyor ve upgrade authority açık."
	case has("program_not_executable"):
		return "İzlenen program hesabı executable durumunu kaybetmiş görünüyor; program durumu kritik inceleme gerektiriyor."
	case has("source_binary_mismatch"):
		return "Dağıtılmış program bytecode'u sağlanan kaynak manifestiyle doğrulanmış biçimde uyuşmuyor."
	case has("upgrade_authority_open"):
		return "Programın upgrade authority yetkisi açık; program kodu daha sonra değiştirilebilir."
	default:
		return "Doğrulanmış program kontrol riski gözlendi."
	}
}

func publicProgramRiskTitle(item publicProgramRisk) string {
	if item.Type == "program_deployment_changed" {
		return "Solana program dağıtımı değişti"
	}
	return "Solana program kontrol riski"
}

func publicProgramRiskLimitations() []string {
	return []string{
		"Bu yayın zincir üstü teknik program durumunu gösterir; aktör kimliği, niyet, saldırı veya suç isnadı oluşturmaz.",
		"Açık upgrade authority tek başına kötü niyet kanıtı değildir; programın değiştirilebilir olduğunu gösterir.",
		"Kaynak eşleşmesi yalnızca bağımsız manifest sağlandığında değerlendirilebilir; doğrulanmamış kaynak eksikliği uyuşmazlık sayılmaz.",
		"Bu kanıt deterministik karar motoruna otomatik verdict yetkisi vermez.",
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
