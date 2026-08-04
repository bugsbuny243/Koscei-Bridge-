package handlers

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const publicRadarLiveWindow = 24 * time.Hour

type publicRadarLiveEvent struct {
	ID             string    `json:"id"`
	Type           string    `json:"type"`
	Title          string    `json:"title"`
	TargetKind     string    `json:"target_kind"`
	Target         string    `json:"target"`
	Grade          string    `json:"grade"`
	RiskIndex      int       `json:"risk_index"`
	RiskLevel      string    `json:"risk_level"`
	Verdict        string    `json:"verdict"`
	Recommendation string    `json:"recommendation"`
	EvidenceRows   int       `json:"evidence_rows"`
	OccurredAt     time.Time `json:"occurred_at"`
	Source         string    `json:"source"`
	Provider       string    `json:"provider"`
	EventType      string    `json:"event_type"`
	RuleVersion    string    `json:"rule_version"`
	Verifiable     bool      `json:"verifiable"`
}

// PublicRadarLiveFeed exposes the actual signed ARVIS radar stream. Unlike the
// immutable case registry, this endpoint does not require an owner publication;
// it projects only recent customer-visible A-F verdicts backed by verified
// evidence and strips raw targets and internal worker details.
func (h *Handler) PublicRadarLiveFeed(w http.ResponseWriter, r *http.Request) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "status": "database_unavailable", "events": []publicRadarLiveEvent{},
		})
		return
	}

	items, err := services.NewSecurityRadarStore(db).LatestVerdicts(r.Context(), 100)
	if err != nil {
		status := http.StatusServiceUnavailable
		code := "radar_live_unavailable"
		if isMissingRelation(err) {
			status = http.StatusOK
			code = "schema_pending"
		}
		writeJSON(w, status, map[string]any{
			"ok": status == http.StatusOK, "status": code, "events": []publicRadarLiveEvent{},
			"generated_at": time.Now().UTC(), "refresh_seconds": 15,
		})
		return
	}

	now := time.Now().UTC()
	events := buildPublicRadarLiveEvents(items, now)
	gradeCounts := map[string]int{"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
	providerCounts := map[string]int{}
	riskCounts := map[string]int{}
	var lastResultAt any
	for index, event := range events {
		gradeCounts[event.Grade]++
		providerCounts[event.Provider]++
		riskCounts[event.RiskLevel]++
		if index == 0 {
			lastResultAt = event.OccurredAt
		}
	}

	stream := h.securityRadarStreamStats(r.Context())
	pipelineStatus := metricString(stream, "pipeline_status")
	if pipelineStatus == "" {
		pipelineStatus = "unknown"
	}

	w.Header().Set("Cache-Control", "public, max-age=5, stale-while-revalidate=15")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"status":          "operational",
		"generated_at":    now,
		"refresh_seconds": 15,
		"window_hours":    24,
		"pipeline_status": pipelineStatus,
		"summary": map[string]any{
			"live_results":    len(events),
			"grade_counts":    gradeCounts,
			"provider_counts": providerCounts,
			"risk_counts":     riskCounts,
			"last_result_at":  lastResultAt,
		},
		"pipeline": map[string]any{
			"status":                pipelineStatus,
			"raw_stream_events":     stream["raw_stream_events"],
			"recognized_events":     stream["recognized_events"],
			"visible_verdicts":      stream["visible_verdicts"],
			"processing_active":     stream["processing_active"],
			"processing_completed":  stream["processing_completed"],
			"processing_failed":     stream["processing_failed"],
			"last_stream_event_at":  stream["last_stream_event_at"],
			"last_processed_at":     stream["last_processed_at"],
			"source_health":         h.arvisSourceHealth(r.Context()),
		},
		"events": events,
		"boundaries": []string{
			"Yalnız son 24 saatte üretilmiş, imzalı ve doğrulanmış kanıta bağlı A/B/C/D/F sonuçları gösterilir.",
			"Bu akış owner tarafından ayrıca yayınlanmış dossier listesi değildir; canlı ARVIS radar kararlarının güvenli public izdüşümüdür.",
			"Ham hedef adresi, özel müşteri taraması, owner secret ve iç worker ayrıntısı public yanıta girmez.",
			"WITHHOLD ve eksik kanıtlı sonuçlar harf notu gibi gösterilmez.",
		},
	})
}

func buildPublicRadarLiveEvents(items []services.SecurityRadarVerdictRecord, now time.Time) []publicRadarLiveEvent {
	cutoff := now.Add(-publicRadarLiveWindow)
	out := make([]publicRadarLiveEvent, 0, len(items))
	for _, item := range items {
		grade, ok := publicRadarLetterGrade(item.Grade)
		if !ok || item.ModuleID != services.ModuleFinalVerdictEngine || !item.Signed || strings.TrimSpace(item.Signature) == "" || !radarSignalsVerified(item.Signals) {
			continue
		}
		if visible, exists := item.Signals["customer_detail_visible"]; exists {
			if allowed, ok := visible.(bool); ok && !allowed {
				continue
			}
		}
		if item.CreatedAt.IsZero() || item.CreatedAt.Before(cutoff) || item.CreatedAt.After(now.Add(5*time.Minute)) {
			continue
		}
		riskLevel := strings.ToLower(strings.TrimSpace(item.RiskLevel))
		if riskLevel == "" {
			riskLevel = "unknown"
		}
		provider := firstPublicDossierString(item.Provider, item.Source, "unknown")
		targetKind := firstPublicDossierString(item.TargetType, "token")
		riskIndex := item.RiskIndex
		if riskIndex < 0 {
			riskIndex = 0
		}
		if riskIndex > 100 {
			riskIndex = 100
		}
		out = append(out, publicRadarLiveEvent{
			ID:             item.ID,
			Type:           "signed_radar_verdict",
			Title:          grade + " · " + strings.ToUpper(riskLevel),
			TargetKind:     targetKind,
			Target:         maskPublicDossierTarget(item.Target),
			Grade:          grade,
			RiskIndex:      riskIndex,
			RiskLevel:      riskLevel,
			Verdict:        strings.TrimSpace(item.Verdict),
			Recommendation: strings.TrimSpace(item.Recommendation),
			EvidenceRows:   len(item.Evidence),
			OccurredAt:     item.CreatedAt.UTC(),
			Source:         firstPublicDossierString(item.Source, "arvis_stream"),
			Provider:       provider,
			EventType:      strings.TrimSpace(item.EventType),
			RuleVersion:    strings.TrimSpace(item.RuleVersion),
			Verifiable:     true,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].OccurredAt.After(out[j].OccurredAt) })
	return out
}

func publicRadarLetterGrade(value string) (string, bool) {
	grade := strings.ToUpper(strings.TrimSpace(value))
	switch grade {
	case "A", "B", "C", "D", "F":
		return grade, true
	default:
		return "", false
	}
}
