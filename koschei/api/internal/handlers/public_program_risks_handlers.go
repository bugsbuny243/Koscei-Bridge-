package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

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
	findings, err := h.loadPublicContractFindings(r.Context(), 40)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "status": "unavailable", "events": []publicUnifiedSOCEvent{},
		})
		return
	}

	actorCases, tokenCases, verified, observed, featured := 0, 0, 0, 0, 0
	criticalPrograms, highPrograms := 0, 0
	criticalFindings, highFindings := 0, 0
	events := make([]publicUnifiedSOCEvent, 0, len(cases)+len(risks)+len(findings))
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
	for _, item := range findings {
		if item.Severity == "critical" {
			criticalFindings++
		} else if item.Severity == "high" {
			highFindings++
		}
		events = append(events, publicUnifiedSOCEvent{
			Type: item.Type, IdentityKey: item.FindingRef, EventRef: item.FindingRef,
			Title: item.Title, TargetKind: "solana_program_source", Target: item.ProgramID,
			Severity: item.Severity, ChangeTypes: []string{item.RuleID, item.Confidence, item.LifecycleStatus},
			Evidence: item.EvidenceRows, OccurredAt: item.PublishedAt, PublicURL: item.PublicURL,
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
			"contract_finding_events": len(findings), "critical_contract_findings": criticalFindings,
			"high_contract_findings": highFindings,
			"verified_evidence_rows": verified, "observed_evidence_rows": observed,
			"last_published_at": lastPublished,
		},
		"events": events,
		"boundaries": []string{
			"Özel müşteri taramaları ve iç worker ayrıntıları yayımlanmaz.",
			"Program alarmı yalnızca değişmez snapshot/event hash'i bulunan HIGH veya CRITICAL zincir üstü teknik durumdan üretilir.",
			"Akıllı kontrat kaynak bulgusu yalnız owner açıkça yayınladığında görünür; kaynak yolu ve eşleşen kod parçası redakte edilir.",
			"Statik bulgu exploit, erişilebilirlik, varlık etkisi, kötü niyet veya suç kanıtı değildir.",
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
