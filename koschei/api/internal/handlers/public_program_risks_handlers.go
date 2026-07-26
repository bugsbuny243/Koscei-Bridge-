package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

type publicUnifiedSOCEvent struct {
	Type             string    `json:"type"`
	IdentityKey      string    `json:"identity_key"`
	EventRef         string    `json:"event_ref,omitempty"`
	CaseRef          string    `json:"case_ref,omitempty"`
	Title            string    `json:"title"`
	TargetKind       string    `json:"target_kind"`
	Target           string    `json:"target"`
	Verdict          string    `json:"verdict,omitempty"`
	Severity         string    `json:"severity,omitempty"`
	ChangeTypes      []string  `json:"change_types,omitempty"`
	Evidence         int       `json:"evidence_rows"`
	OccurredAt       time.Time `json:"occurred_at"`
	PublicURL        string    `json:"public_url"`
	BundleHash       string    `json:"bundle_hash,omitempty"`
	VerificationHash string    `json:"verification_hash,omitempty"`
	Verifiable       bool      `json:"verifiable"`
	Description      string    `json:"description"`
}

type programRiskPublicationRequest struct {
	EvidenceRef   string `json:"evidence_ref"`
	Status        string `json:"status"`
	PublicTitle   string `json:"public_title"`
	PublicSummary string `json:"public_summary"`
}

func (h *Handler) PublicUnifiedSOCFeed(w http.ResponseWriter, r *http.Request) {
	cases, err := h.loadCurrentPublicCases(r.Context(), 40)
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
		events = append(events, publicUnifiedSOCEvent{
			Type: "immutable_case_published", IdentityKey: "case:" + item.CaseRef, CaseRef: item.CaseRef, Title: item.Title,
			TargetKind: item.TargetKind, Target: item.TargetDisplay, Verdict: verdict,
			Evidence: item.EvidenceRows, OccurredAt: item.PublishedAt, PublicURL: "/case/" + item.CaseRef,
			BundleHash: item.BundleHash, Verifiable: item.BundleHash != "",
			Description: "Kullanıcısı tarafından görünür yapılan değişmez ARVIS güvenlik vakası.",
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
			Title: item.Title, TargetKind: "solana_program", Target: item.ProgramID,
			Severity: item.Severity, ChangeTypes: append([]string(nil), item.RiskTypes...),
			Evidence: item.EvidenceRows, OccurredAt: item.OccurredAt, PublicURL: item.PublicURL,
			VerificationHash: item.VerificationHash, Verifiable: item.VerificationHash != "", Description: item.Summary,
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
		"ok":              true,
		"status":          "operational",
		"generated_at":    time.Now().UTC(),
		"refresh_seconds": 15,
		"summary": map[string]any{
			"published_cases": len(cases), "featured_cases": featured,
			"actor_cases": actorCases, "token_cases": tokenCases,
			"program_risk_events": len(risks), "critical_program_events": criticalPrograms,
			"high_program_events":    highPrograms,
			"verified_evidence_rows": verified, "observed_evidence_rows": observed,
			"last_published_at": lastPublished,
		},
		"events": events,
		"boundaries": []string{
			"Vaka görünürlüğünü dosyayı üreten kullanıcı veya API hesabı kontrol eder; owner yalnız moderasyon yapar.",
			"Program alarmı yalnız açıkça yayımlanmış HIGH veya CRITICAL teknik kanıttan üretilir.",
			"Açık upgrade authority teknik kontrol riski demektir; tek başına kötü niyet, saldırı veya dolandırıcılık iddiası değildir.",
			"Kaynak doğrulanmamışsa uyuşmazlık varmış gibi gösterilmez.",
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
		"ok":           true,
		"generated_at": time.Now().UTC(),
		"count":        len(items),
		"risks":        items,
		"publication_policy": map[string]any{
			"creator_or_monitor_owner_controls_visibility": true,
			"minimum_severity":                       "high",
			"private_evidence_is_private_by_default": true,
			"verdict_authority":                      false,
			"identity_or_wrongdoing_claim":           false,
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

// ProgramRiskPublication lets a user/API account publish evidence produced by
// its own Program Sentinel subscription. Owner access remains an emergency
// moderation path and may publish or hide any eligible evidence.
func (h *Handler) ProgramRiskPublication(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.DB == nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Program risk publication database is unavailable")
		return
	}
	requester := dossierRequester(r)
	if requester == "owner" && !dossierOwnerCredentialPresent(r) {
		writeAPIError(w, http.StatusUnauthorized, APICodeUnauthorized, "Authenticated publisher is required")
		return
	}
	var input programRiskPublicationRequest
	if err := decodeJSON(r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Invalid program risk publication request")
		return
	}
	input.EvidenceRef = strings.TrimSpace(input.EvidenceRef)
	input.Status = strings.ToLower(strings.TrimSpace(input.Status))
	input.PublicTitle = boundedPublicDossierText(input.PublicTitle, 160)
	input.PublicSummary = boundedPublicDossierText(input.PublicSummary, 600)
	if !publicProgramRiskRefPattern.MatchString(input.EvidenceRef) {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "A valid KDS1 or KDCE1 evidence_ref is required")
		return
	}
	if input.Status != "public" && input.Status != "hidden" && input.Status != "draft" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "status must be public, hidden or draft")
		return
	}
	owned, eligible, err := h.programRiskPublicationAccess(r, input.EvidenceRef, requester)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Program risk evidence could not be verified")
		return
	}
	if !eligible {
		writeAPIError(w, http.StatusUnprocessableEntity, APICodeInvalidInput, "Evidence is not a current HIGH or CRITICAL public-risk candidate")
		return
	}
	if !owned {
		writeAPIError(w, http.StatusForbidden, APICodeForbidden, "Only the evidence creator can change public visibility")
		return
	}

	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Publication transaction could not start")
		return
	}
	defer tx.Rollback()
	previousStatus := ""
	previousExists := true
	if err := tx.QueryRowContext(r.Context(), `SELECT status FROM program_risk_publications WHERE evidence_ref=$1`, input.EvidenceRef).Scan(&previousStatus); err != nil {
		if err == sql.ErrNoRows {
			previousExists = false
		} else {
			writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Publication state could not be read")
			return
		}
	}
	_, err = tx.ExecContext(r.Context(), `
		INSERT INTO program_risk_publications
		(evidence_ref,status,public_title,public_summary,published_by,published_at,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,CASE WHEN $2='public' THEN now() ELSE NULL END,now(),now())
		ON CONFLICT(evidence_ref) DO UPDATE SET
		 status=EXCLUDED.status,public_title=EXCLUDED.public_title,public_summary=EXCLUDED.public_summary,
		 published_by=EXCLUDED.published_by,
		 published_at=CASE WHEN EXCLUDED.status='public' THEN COALESCE(program_risk_publications.published_at,now()) ELSE program_risk_publications.published_at END,
		 updated_at=now()`, input.EvidenceRef, input.Status, input.PublicTitle, input.PublicSummary, requester)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Publication state could not be saved")
		return
	}
	action := programRiskPublicationAction(previousExists, previousStatus, input.Status)
	stateJSON, _ := json.Marshal(map[string]any{"status": input.Status, "public_title": input.PublicTitle})
	if _, err := tx.ExecContext(r.Context(), `
		INSERT INTO program_risk_publication_events(evidence_ref,action,actor,publication_state)
		VALUES($1,$2,$3,$4::jsonb)`, input.EvidenceRef, action, requester, string(stateJSON)); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Publication audit event could not be saved")
		return
	}
	if err := tx.Commit(); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Publication transaction could not be committed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": input.Status, "action": action, "publisher": requester, "evidence_ref": input.EvidenceRef})
}

func (h *Handler) programRiskPublicationAccess(r *http.Request, ref, requester string) (owned bool, eligible bool, err error) {
	if strings.HasPrefix(ref, "KDCE1-") {
		err = h.DB.QueryRowContext(r.Context(), `
			SELECT
			  ($2='owner' OR EXISTS(SELECT 1 FROM defense_program_monitor_subscriptions s WHERE s.monitor_ref=m.monitor_ref AND s.auth_subject=$2)) AS owned,
			  (e.severity IN ('high','critical') AND e.change_types ?| ARRAY['loader_changed','programdata_address_changed','bytecode_changed','upgrade_authority_opened','upgrade_authority_changed']) AS eligible
			FROM defense_program_change_events e
			JOIN defense_program_monitors m ON m.monitor_ref=e.monitor_ref
			WHERE e.event_ref=$1`, ref, requester).Scan(&owned, &eligible)
		if err == sql.ErrNoRows {
			return false, false, nil
		}
		return owned, eligible, err
	}
	err = h.DB.QueryRowContext(r.Context(), `
		SELECT
		  ($2='owner' OR EXISTS(SELECT 1 FROM defense_program_monitors m JOIN defense_program_monitor_subscriptions s ON s.monitor_ref=m.monitor_ref WHERE m.last_snapshot_ref=d.snapshot_ref AND s.auth_subject=$2)) AS owned,
		  ((d.upgrade_authority_open OR d.match_status='mismatched' OR NOT d.executable)
		   AND NOT EXISTS(SELECT 1 FROM defense_program_deployments newer WHERE newer.program_id=d.program_id AND newer.network=d.network AND (newer.created_at>d.created_at OR (newer.created_at=d.created_at AND newer.snapshot_ref>d.snapshot_ref)))) AS eligible
		FROM defense_program_deployments d WHERE d.snapshot_ref=$1`, ref, requester).Scan(&owned, &eligible)
	if err == sql.ErrNoRows {
		return false, false, nil
	}
	return owned, eligible, err
}

func programRiskPublicationAction(exists bool, previousStatus, nextStatus string) string {
	if !exists {
		if nextStatus == "public" {
			return "publish"
		}
		return nextStatus
	}
	if previousStatus == nextStatus {
		return "update"
	}
	switch nextStatus {
	case "public":
		return "publish"
	case "hidden":
		return "hide"
	default:
		return "draft"
	}
}
