package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var publicDossierCaseRefPattern = regexp.MustCompile(`^KD1-[a-z2-7]{32}$`)

const publicDossierRedactionProfile = "public-onchain-v1"

type dossierPublicationRequest struct {
	CaseRef          string `json:"case_ref"`
	Status           string `json:"status"`
	PublicTitle      string `json:"public_title"`
	PublicSummary    string `json:"public_summary"`
	Featured         bool   `json:"featured"`
	RedactionProfile string `json:"redaction_profile"`
}

type publicDossierCase struct {
	CaseRef                     string    `json:"case_ref"`
	PublicURL                   string    `json:"public_url"`
	Title                       string    `json:"title"`
	Summary                     string    `json:"summary"`
	Featured                    bool      `json:"featured"`
	PublishedAt                 time.Time `json:"published_at"`
	ProducedAt                  time.Time `json:"produced_at"`
	DossierVersion              string    `json:"dossier_version"`
	BundleHash                  string    `json:"bundle_hash"`
	TargetKind                  string    `json:"target_kind"`
	TargetID                    string    `json:"target_id"`
	TargetDisplay               string    `json:"target_display"`
	Network                     string    `json:"network"`
	VerdictGrade                string    `json:"verdict_grade,omitempty"`
	VerdictStatus               string    `json:"verdict_status,omitempty"`
	RulesetVersion              string    `json:"ruleset_version,omitempty"`
	EvidenceRows                int       `json:"evidence_rows"`
	VerifiedRows                int       `json:"verified_rows"`
	ObservedRows                int       `json:"observed_rows"`
	InferredRows                int       `json:"inferred_rows"`
	UnknownRows                 int       `json:"unknown_rows"`
	AcceptancePass              int       `json:"acceptance_pass"`
	AcceptanceFail              int       `json:"acceptance_fail"`
	AcceptanceNotInvestigated   int       `json:"acceptance_not_investigated"`
	CreatedTokenHistoryCount    int       `json:"created_token_history_count"`
	RedactionProfile            string    `json:"redaction_profile"`
	IndependentVerificationPath string    `json:"independent_verification_path"`
}

type publicSOCEvent struct {
	Type        string    `json:"type"`
	CaseRef     string    `json:"case_ref"`
	Title       string    `json:"title"`
	TargetKind  string    `json:"target_kind"`
	Target      string    `json:"target"`
	Verdict     string    `json:"verdict,omitempty"`
	Evidence    int       `json:"evidence_rows"`
	OccurredAt  time.Time `json:"occurred_at"`
	PublicURL   string    `json:"public_url"`
	BundleHash  string    `json:"bundle_hash"`
	Verifiable  bool      `json:"verifiable"`
	Description string    `json:"description"`
}

// PublicDossierCases lists only dossiers explicitly published by an owner.
// The immutable bundle remains the source of truth; this route exposes a small,
// read-only discovery projection and never creates, rescans or changes a verdict.
func (h *Handler) PublicDossierCases(w http.ResponseWriter, r *http.Request) {
	limit := publicDossierLimit(r.URL.Query().Get("limit"), 24, 100)
	cases, err := h.loadPublicDossierCases(r, limit)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "error": "public_cases_unavailable", "cases": []publicDossierCase{},
		})
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=15, stale-while-revalidate=60")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"generated_at": time.Now().UTC(),
		"count": len(cases),
		"publication_policy": map[string]any{
			"explicit_owner_publish_required": true,
			"private_customer_investigations_excluded": true,
			"identity_or_wrongdoing_claim": false,
			"immutable_source_bundle": true,
		},
		"cases": cases,
	})
}

// PublicSOCFeed is the first public, evidence-only SOC projection. It is built
// exclusively from explicitly published immutable dossiers and is safe to poll.
func (h *Handler) PublicSOCFeed(w http.ResponseWriter, r *http.Request) {
	cases, err := h.loadPublicDossierCases(r, 20)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "status": "unavailable", "events": []publicSOCEvent{},
		})
		return
	}
	actorCases, tokenCases, verified, observed, featured := 0, 0, 0, 0, 0
	events := make([]publicSOCEvent, 0, len(cases))
	for _, item := range cases {
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
		events = append(events, publicSOCEvent{
			Type: "immutable_case_published", CaseRef: item.CaseRef, Title: item.Title,
			TargetKind: item.TargetKind, Target: item.TargetDisplay, Verdict: verdict,
			Evidence: item.EvidenceRows, OccurredAt: item.PublishedAt, PublicURL: item.PublicURL,
			BundleHash: item.BundleHash, Verifiable: item.BundleHash != "",
			Description: "Açıkça yayınlanmış değişmez ARVIS kanıt vakası.",
		})
	}
	var lastPublished any
	if len(cases) > 0 {
		lastPublished = cases[0].PublishedAt
	}
	w.Header().Set("Cache-Control", "public, max-age=10, stale-while-revalidate=30")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"status": "operational",
		"generated_at": time.Now().UTC(),
		"refresh_seconds": 15,
		"summary": map[string]any{
			"published_cases": len(cases), "featured_cases": featured,
			"actor_cases": actorCases, "token_cases": tokenCases,
			"verified_evidence_rows": verified, "observed_evidence_rows": observed,
			"last_published_at": lastPublished,
		},
		"events": events,
		"boundaries": []string{
			"Only owner-published immutable dossiers appear here.",
			"No private customer scan, secret, internal worker detail or real-world identity attribution is exposed.",
			"No new event is shown when no new verifiable publication exists.",
		},
	})
}

// OwnerDossierPublication controls discovery visibility only. It never mutates
// dossier_exports or dossier_source_snapshots.
func (h *Handler) OwnerDossierPublication(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.DB == nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Dossier publication database is unavailable")
		return
	}
	var input dossierPublicationRequest
	if err := decodeJSON(r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Invalid publication request")
		return
	}
	input.CaseRef = strings.TrimSpace(input.CaseRef)
	input.Status = strings.ToLower(strings.TrimSpace(input.Status))
	input.PublicTitle = boundedPublicDossierText(input.PublicTitle, 160)
	input.PublicSummary = boundedPublicDossierText(input.PublicSummary, 600)
	input.RedactionProfile = strings.TrimSpace(input.RedactionProfile)
	if input.RedactionProfile == "" {
		input.RedactionProfile = publicDossierRedactionProfile
	}
	if !publicDossierCaseRefPattern.MatchString(input.CaseRef) {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "A valid immutable case_ref is required")
		return
	}
	if input.Status != "public" && input.Status != "hidden" && input.Status != "draft" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "status must be public, hidden or draft")
		return
	}
	if input.RedactionProfile != publicDossierRedactionProfile {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Unsupported public redaction profile")
		return
	}
	if input.Featured && input.Status != "public" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Only public cases can be featured")
		return
	}

	var canonical []byte
	if err := h.DB.QueryRowContext(r.Context(), `SELECT canonical_bundle FROM dossier_exports WHERE case_ref=$1`, input.CaseRef).Scan(&canonical); err != nil {
		if err == sql.ErrNoRows {
			writeAPIError(w, http.StatusNotFound, APICodeNotFound, "Immutable dossier was not found")
			return
		}
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Immutable dossier could not be loaded")
		return
	}
	var bundle dossierBundle
	if json.Unmarshal(canonical, &bundle) != nil || bundle.CaseRef != input.CaseRef || bundle.BundleHash == "" {
		writeAPIError(w, http.StatusConflict, APICodeConflict, "Immutable dossier bundle is invalid")
		return
	}
	if input.PublicTitle == "" {
		input.PublicTitle = defaultPublicDossierTitle(bundle)
	}
	if input.PublicSummary == "" {
		input.PublicSummary = defaultPublicDossierSummary(bundle)
	}

	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Publication transaction could not start")
		return
	}
	defer tx.Rollback()
	previousStatus, previousFeatured := "", false
	previousExists := true
	if err := tx.QueryRowContext(r.Context(), `SELECT status,featured FROM dossier_publications WHERE case_ref=$1`, input.CaseRef).Scan(&previousStatus, &previousFeatured); err != nil {
		if err == sql.ErrNoRows {
			previousExists = false
		} else {
			writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Publication state could not be read")
			return
		}
	}
	_, err = tx.ExecContext(r.Context(), `
		INSERT INTO dossier_publications
			(case_ref,status,public_title,public_summary,featured,redaction_profile,published_at,published_by,created_at,updated_at)
		VALUES
			($1,$2,$3,$4,$5,$6,CASE WHEN $2='public' THEN now() ELSE NULL END,'owner',now(),now())
		ON CONFLICT (case_ref) DO UPDATE SET
			status=EXCLUDED.status,
			public_title=EXCLUDED.public_title,
			public_summary=EXCLUDED.public_summary,
			featured=CASE WHEN EXCLUDED.status='public' THEN EXCLUDED.featured ELSE false END,
			redaction_profile=EXCLUDED.redaction_profile,
			published_at=CASE WHEN EXCLUDED.status='public' THEN COALESCE(dossier_publications.published_at,now()) ELSE dossier_publications.published_at END,
			published_by='owner',
			updated_at=now()`,
		input.CaseRef, input.Status, input.PublicTitle, input.PublicSummary, input.Featured, input.RedactionProfile)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Publication state could not be saved")
		return
	}
	action := publicDossierPublicationAction(previousExists, previousStatus, previousFeatured, input.Status, input.Featured)
	stateJSON, _ := json.Marshal(map[string]any{
		"status": input.Status, "featured": input.Featured,
		"public_title": input.PublicTitle, "redaction_profile": input.RedactionProfile,
	})
	if _, err := tx.ExecContext(r.Context(), `
		INSERT INTO dossier_publication_events (case_ref,action,actor,publication_state)
		VALUES ($1,$2,'owner',$3::jsonb)`, input.CaseRef, action, string(stateJSON)); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Publication audit event could not be saved")
		return
	}
	if err := tx.Commit(); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Publication transaction could not be committed")
		return
	}

	publishedAt := time.Time{}
	if input.Status == "public" {
		_ = h.DB.QueryRowContext(r.Context(), `SELECT published_at FROM dossier_publications WHERE case_ref=$1`, input.CaseRef).Scan(&publishedAt)
	}
	item := buildPublicDossierCase(bundle, input.PublicTitle, input.PublicSummary, input.Featured, publishedAt, input.RedactionProfile)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "status": input.Status, "action": action,
		"case": item,
		"immutable_dossier_unchanged": true,
	})
}

func (h *Handler) loadPublicDossierCases(r *http.Request, limit int) ([]publicDossierCase, error) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return nil, sql.ErrConnDone
	}
	rows, err := db.QueryContext(r.Context(), `
		SELECT p.case_ref,p.public_title,p.public_summary,p.featured,p.redaction_profile,p.published_at,e.canonical_bundle
		FROM dossier_publications p
		JOIN dossier_exports e ON e.case_ref=p.case_ref
		WHERE p.status='public'
		ORDER BY p.featured DESC,p.published_at DESC,p.case_ref
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []publicDossierCase{}
	for rows.Next() {
		var caseRef, title, summary, profile string
		var featured bool
		var publishedAt time.Time
		var canonical []byte
		if err := rows.Scan(&caseRef, &title, &summary, &featured, &profile, &publishedAt, &canonical); err != nil {
			return nil, err
		}
		var bundle dossierBundle
		if json.Unmarshal(canonical, &bundle) != nil || bundle.CaseRef != caseRef || bundle.BundleHash == "" {
			return nil, sql.ErrNoRows
		}
		out = append(out, buildPublicDossierCase(bundle, title, summary, featured, publishedAt, profile))
	}
	return out, rows.Err()
}

func buildPublicDossierCase(bundle dossierBundle, title, summary string, featured bool, publishedAt time.Time, profile string) publicDossierCase {
	target := dossierMap(bundle.Target)
	verdict := dossierMap(bundle.Verdict)
	technical := bundle.TechnicalReport
	card := dossierMap(bundle.VerdictCard)
	rows := dossierSlice(card["signal_rows"])
	verified, observed, inferred, unknown := 0, 0, 0, 0
	for _, raw := range rows {
		state := strings.ToLower(dossierString(dossierMap(raw)["state"]))
		switch state {
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
	acceptance := dossierMap(bundle.ActorAcceptance)
	targetKind := strings.ToLower(firstPublicDossierString(dossierString(target["kind"]), "unknown"))
	targetID := firstPublicDossierString(dossierString(target["id"]), dossierString(target["address"]), dossierString(target["mint"]))
	network := firstPublicDossierString(dossierString(target["network"]), dossierString(technical["network"]), "solana-mainnet")
	if title == "" {
		title = defaultPublicDossierTitle(bundle)
	}
	if summary == "" {
		summary = defaultPublicDossierSummary(bundle)
	}
	return publicDossierCase{
		CaseRef: bundle.CaseRef, PublicURL: "/dossier/" + bundle.CaseRef,
		Title: title, Summary: summary, Featured: featured, PublishedAt: publishedAt.UTC(),
		ProducedAt: bundle.ProducedAt.UTC(), DossierVersion: bundle.DossierVersion,
		BundleHash: bundle.BundleHash, TargetKind: targetKind, TargetID: targetID,
		TargetDisplay: maskPublicDossierTarget(targetID), Network: network,
		VerdictGrade: firstPublicDossierString(dossierString(verdict["grade"]), dossierString(verdict["letter_grade"]), dossierString(verdict["verdict_grade"])),
		VerdictStatus: firstPublicDossierString(dossierString(verdict["status"]), dossierString(verdict["decision"]), dossierString(verdict["state"])),
		RulesetVersion: firstPublicDossierString(dossierString(verdict["ruleset_version"]), dossierString(technical["ruleset_version"])),
		EvidenceRows: len(rows), VerifiedRows: verified, ObservedRows: observed, InferredRows: inferred, UnknownRows: unknown,
		AcceptancePass: publicDossierInt(acceptance["pass_count"]),
		AcceptanceFail: publicDossierInt(acceptance["fail_count"]),
		AcceptanceNotInvestigated: publicDossierInt(acceptance["not_investigated_count"]),
		CreatedTokenHistoryCount: len(dossierSlice(bundle.CreatedTokenHistory)),
		RedactionProfile: profile,
		IndependentVerificationPath: "node oss/verifier/typescript/verify-dossier.mjs ./dossier.json",
	}
}

func defaultPublicDossierTitle(bundle dossierBundle) string {
	target := dossierMap(bundle.Target)
	kind := strings.ToLower(dossierString(target["kind"]))
	id := firstPublicDossierString(dossierString(target["id"]), dossierString(target["address"]), dossierString(target["mint"]))
	label := "ARVIS Evidence Case"
	if kind == "wallet" {
		label = "ARVIS Actor Evidence Case"
	} else if kind == "token" || kind == "token_mint" {
		label = "ARVIS Token Evidence Case"
	}
	if display := maskPublicDossierTarget(id); display != "" {
		return label + " · " + display
	}
	return label + " · " + bundle.CaseRef
}

func defaultPublicDossierSummary(bundle dossierBundle) string {
	card := dossierMap(bundle.VerdictCard)
	rows := dossierSlice(card["signal_rows"])
	return "Deterministik kurallar, kanıt referansları ve bağımsız doğrulama bilgileriyle yayınlanan değişmez Koschei ARVIS vakası. " + strconv.Itoa(len(rows)) + " kanıt satırı içerir."
}

func publicDossierPublicationAction(exists bool, previousStatus string, previousFeatured bool, nextStatus string, nextFeatured bool) string {
	if !exists {
		if nextStatus == "public" {
			return "publish"
		}
		return nextStatus
	}
	if previousStatus != nextStatus {
		switch nextStatus {
		case "public":
			return "publish"
		case "hidden":
			return "hide"
		default:
			return "draft"
		}
	}
	if previousFeatured != nextFeatured {
		if nextFeatured {
			return "feature"
		}
		return "unfeature"
	}
	return "update"
}

func publicDossierLimit(raw string, fallback, maximum int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return fallback
	}
	if value > maximum {
		return maximum
	}
	return value
}

func publicDossierInt(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return int(parsed)
	case string:
		parsed, _ := strconv.Atoi(strings.TrimSpace(typed))
		return parsed
	default:
		return 0
	}
}

func firstPublicDossierString(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func maskPublicDossierTarget(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 16 {
		return value
	}
	return value[:7] + "…" + value[len(value)-7:]
}

func boundedPublicDossierText(value string, maximum int) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) > maximum {
		value = string(runes[:maximum])
	}
	return value
}
