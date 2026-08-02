package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type securityRadarInput struct {
	Target  string `json:"target"`
	Address string `json:"address"`
	Network string `json:"network"`
	Mode    string `json:"mode"`
}

type securityRadarFeedItem struct {
	services.SecurityRadarVerdictRecord
	OccurrenceCount int            `json:"occurrence_count"`
	RiskEvents      int            `json:"risk_events"`
	MonitorEvents   int            `json:"monitor_events"`
	MaxRiskIndex    int            `json:"max_risk_index"`
	MinRiskIndex    int            `json:"min_risk_index"`
	FirstSeenAt     time.Time      `json:"first_seen_at"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
	Summary         map[string]any `json:"summary"`
}

type securityRadarFeedAccumulator struct {
	Best            services.SecurityRadarVerdictRecord
	OccurrenceCount int
	RiskEvents      int
	MonitorEvents   int
	MaxRiskIndex    int
	MinRiskIndex    int
	FirstSeenAt     time.Time
	LastSeenAt      time.Time
	RuleVersions    map[string]bool
	Providers       map[string]bool
}

func (h *Handler) SecurityRadarFeed(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("graph")), "1") || strings.TrimSpace(r.URL.Query().Get("verdict_id")) != "" {
		h.SecurityRadarGraph(w, r)
		return
	}
	base := map[string]any{"ok": true, "source": "koschei_security_radar", "provider": services.SecurityRadarProvider, "watch_mode": services.SecurityRadarWatchMode, "architecture_arm_count": 14}
	if h == nil || h.DBRead == nil {
		base["items"] = []any{}
		base["stream"] = map[string]any{"enabled": streamEnvEnabled(), "wss_configured": streamWSSConfigured(), "pipeline_status": "database_unavailable"}
		base["timeline"] = []any{}
		writeJSON(w, http.StatusOK, base)
		return
	}
	items, err := services.NewSecurityRadarStore(h.DBRead).LatestVerdicts(r.Context(), 100)
	if isMissingRelation(err) {
		base["items"] = []any{}
		base["source"] = "schema_pending"
		base["stream"] = map[string]any{"enabled": streamEnvEnabled(), "wss_configured": streamWSSConfigured(), "schema_pending": true, "pipeline_status": "schema_pending"}
		base["timeline"] = []any{}
		writeJSON(w, http.StatusOK, base)
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, APICodeIntegrationError, "Radar feed unavailable")
		return
	}
	verified := make([]services.SecurityRadarVerdictRecord, 0, len(items))
	for _, item := range items {
		if visible, exists := item.Signals["customer_detail_visible"]; exists {
			if allowed, ok := visible.(bool); ok && !allowed {
				continue
			}
		}
		if item.Signed && radarSignalsVerified(item.Signals) && item.ModuleID == services.ModuleFinalVerdictEngine {
			verified = append(verified, item)
		}
	}
	aggregated := aggregateSecurityRadarFeedItems(verified)
	base["items"] = aggregated
	base["raw_item_count"] = len(verified)
	base["deduped_item_count"] = len(aggregated)
	base["stream"] = h.securityRadarStreamStats(r.Context())
	base["timeline"] = h.securityRadarStreamTimeline(r.Context(), 14)
	writeJSON(w, http.StatusOK, base)
}

func (h *Handler) SecurityRadarCheck(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, APICodeUnauthorized, "Unauthorized")
		return
	}
	claimEmail := normalizedClaimEmail(claims)
	if _, err := h.requirePremiumOutput(claims.Sub, claimEmail); err != nil {
		writeJSON(w, http.StatusPaymentRequired, insufficientOutputsResponse())
		return
	}
	var input securityRadarInput
	if err := decodeJSON(r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Invalid request body")
		return
	}
	target := strings.TrimSpace(firstNonEmptyString(input.Target, input.Address))
	if target == "" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "target is required")
		return
	}
	input.Network = strings.TrimSpace(input.Network)
	if input.Network == "" {
		input.Network = "solana-mainnet"
	}
	classification := classifyRadarTarget(r.Context(), target)
	if radarTargetWalletInvestigationAllowed(classification) {
		h.securityRadarWalletCheck(w, r, claims.Sub, claimEmail, target, input.Network, classification)
		return
	}
	if !radarTargetTokenVerdictAllowed(classification) {
		services.WriteSecurityAuditEvent(r.Context(), h.DB, securityAuditFromRequest(r, "radar_check_wrong_target_type", "customer", "warning", map[string]any{"network": input.Network, "target": target, "target_type": classification.Type}))
		statusCode := http.StatusUnprocessableEntity
		if classification.Type == radarTargetUnknown {
			statusCode = http.StatusServiceUnavailable
		}
		writeJSON(w, statusCode, map[string]any{"ok": false, "error": "token_mint_required", "message": radarTargetRejectionMessage(classification), "target": target, "target_classification": classification, "charged": false, "final_verdict": map[string]any{"risk_index": nil, "risk_level": "unknown", "signed": false, "recommendation": classification.Type + "_intelligence_required"}})
		return
	}

	mode := firstNonEmptyString(input.Mode, "manual_dashboard_check")
	services.WriteSecurityAuditEvent(r.Context(), h.DB, securityAuditFromRequest(r, "radar_check_requested", "customer", "info", map[string]any{"network": input.Network, "mode": mode, "target": target}))
	ctx, cancel := context.WithTimeout(r.Context(), 240*time.Second)
	defer cancel()

	assembly := h.buildUnifiedInvestigationReport(ctx, target, input.Network, mode)
	hasLiveEvidence := services.SecurityRadarHasLiveEvidence(assembly.Core.Bundle)
	if !hasLiveEvidence {
		services.WriteSecurityAuditEvent(ctx, h.DB, securityAuditFromRequest(r, "radar_check_evidence_pending", "customer", "warning", map[string]any{"network": input.Network, "target": target}))
	}
	_ = h.saveSecurityRadarBundle(ctx, claims.Sub, "manual_check", assembly.Core.Bundle)

	charged := false
	if hasLiveEvidence {
		if err := h.consumePremiumOutput(claims.Sub, claimEmail, "security_radar_check"); err != nil {
			writeJSON(w, http.StatusPaymentRequired, insufficientOutputsResponse())
			return
		}
		charged = true
	}
	status := customerInvestigationStatus(assembly.UnifiedVerdict, hasLiveEvidence)
	h.logTool(claimEmail, "security_radar_check", status)
	h.trackEvent(claimEmail, "security_radar_check", r.URL.Path)
	writeJSON(w, http.StatusOK, customerInvestigationEnvelope(assembly, charged))
}

func (h *Handler) SecurityRiskBadge(w http.ResponseWriter, r *http.Request) {
	address := strings.TrimSpace(r.URL.Query().Get("address"))
	if address == "" {
		address = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	if address == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "address parameter is required"})
		return
	}
	network := strings.TrimSpace(r.URL.Query().Get("network"))
	if network == "" {
		network = "solana-mainnet"
	}
	classification := classifyRadarTarget(r.Context(), address)
	if !radarTargetTokenVerdictAllowed(classification) {
		statusCode := http.StatusUnprocessableEntity
		if classification.Type == radarTargetUnknown {
			statusCode = http.StatusServiceUnavailable
		}
		writeJSON(w, statusCode, map[string]any{"ok": false, "error": "token_mint_required", "message": radarTargetRejectionMessage(classification), "address": address, "target_classification": classification, "risk_index": nil, "risk_level": "unknown", "signed": false})
		return
	}
	analysis := services.AnalyzeArvisRadars(services.SecurityRadarRequest{Target: address, Network: network, Mode: "public_badge"})
	bundle := services.EvidenceBackedSecurityRadarBundle(analysis.Bundle)
	final := services.ArvisFinalFromBundle(bundle)
	if !services.SecurityRadarHasLiveEvidence(bundle) || !final.Signed {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "real_data_unavailable", "message": services.SecurityRadarInsufficientEvidenceMessage, "address": address, "grade": final.Grade, "risk_index": final.RiskIndex, "risk_level": final.RiskLevel, "signed": false})
		return
	}
	if h != nil && h.DB != nil {
		_ = h.saveSecurityRadarBundle(r.Context(), "", "public_badge", bundle)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "address": address, "grade": final.Grade, "risk_index": final.RiskIndex, "risk_level": final.RiskLevel, "verdict": final.Verdict, "recommendation": final.Recommendation, "rule_version": final.RuleVersion, "signed": final.Signed, "signature": final.Signature, "verified_arm_count": bundle.Metadata["verified_arm_count"]})
}

func (h *Handler) OwnerRadarSummary(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.DBRead == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "radar": map[string]any{}})
		return
	}
	metrics := map[string]any{"rule_version": services.SecurityRadarRuleVersion, "architecture_arm_count": 14, "sbx1_stream_enabled": streamEnvEnabled(), "sbx1_wss_configured": streamWSSConfigured()}
	count := func(key, query string) {
		var value int64
		if err := h.DBRead.QueryRowContext(r.Context(), query).Scan(&value); err == nil {
			metrics[key] = value
		}
	}
	text := func(key, query string) {
		var value string
		if err := h.DBRead.QueryRowContext(r.Context(), query).Scan(&value); err == nil {
			metrics[key] = value
		}
	}
	verifiedSQL := radarVerifiedEvidenceSQL()
	count("radar_events", `SELECT count(*) FROM security_radar_events`)
	count("radar_verdicts", `SELECT count(*) FROM security_radar_verdicts WHERE module_id='final_verdict_engine' AND signed=true AND `+verifiedSQL)
	count("badge_consumers", `SELECT count(DISTINCT target) FROM security_radar_events WHERE COALESCE(source,'')='public_badge'`)
	count("critical_risk_count", `SELECT count(*) FROM security_radar_verdicts WHERE module_id='final_verdict_engine' AND risk_level='critical' AND signed=true AND `+verifiedSQL)
	count("high_risk_count", `SELECT count(*) FROM security_radar_verdicts WHERE module_id='final_verdict_engine' AND risk_level='high' AND signed=true AND `+verifiedSQL)
	count("module_usage", `SELECT count(DISTINCT module_id) FROM security_radar_verdicts WHERE module_id <> 'final_verdict_engine' AND signed=true AND `+verifiedSQL)
	count("sbx1_stream_events", `SELECT count(*) FROM security_radar_stream_events`)
	count("sbx1_recognized_events", `SELECT count(*) FROM security_radar_stream_events WHERE module_id <> 'unknown'`)
	text("sbx1_last_event_at", `SELECT COALESCE(max(created_at)::text,'') FROM security_radar_stream_events`)
	h.addArvisProcessingMetrics(r.Context(), metrics)
	metrics["pipeline_status"] = arvisPipelineStatus(metrics)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "radar": metrics})
}

func (h *Handler) securityRadarStreamStats(ctx context.Context) map[string]any {
	metrics := map[string]any{"enabled": streamEnvEnabled(), "wss_configured": streamWSSConfigured(), "architecture_arm_count": 14, "runtime_window_minutes": 15}
	if h == nil || h.DBRead == nil {
		metrics["pipeline_status"] = "database_unavailable"
		return metrics
	}
	count := func(key, query string) {
		var value int64
		if err := h.DBRead.QueryRowContext(ctx, query).Scan(&value); err == nil {
			metrics[key] = value
		}
	}
	text := func(key, query string) {
		var value string
		if err := h.DBRead.QueryRowContext(ctx, query).Scan(&value); err == nil {
			metrics[key] = value
		}
	}
	verifiedSQL := radarVerifiedEvidenceSQL()
	count("raw_stream_events", `SELECT count(*) FROM security_radar_stream_events`)
	count("recognized_events", `SELECT count(*) FROM security_radar_stream_events WHERE module_id <> 'unknown'`)
	count("enriched_mints", `SELECT count(*) FROM security_radar_stream_events WHERE evidence_quality='transaction_enriched_mint'`)
	count("visible_verdicts", `SELECT count(*) FROM security_radar_verdicts WHERE module_id='final_verdict_engine' AND signed=true AND created_at > now() - interval '24 hours' AND `+verifiedSQL)
	count("signed_verdicts_total", `SELECT count(*) FROM security_radar_verdicts WHERE module_id='final_verdict_engine' AND signed=true AND `+verifiedSQL)
	count("runtime_engines", `SELECT count(DISTINCT module_id) FROM security_radar_verdicts WHERE module_id <> 'final_verdict_engine' AND source='arvis_stream' AND signed=true AND created_at > now() - interval '15 minutes' AND `+verifiedSQL)
	text("last_stream_event_at", `SELECT COALESCE(max(created_at)::text,'') FROM security_radar_stream_events`)
	text("last_stream_signature", `SELECT COALESCE(signature,'') FROM security_radar_stream_events WHERE signature IS NOT NULL ORDER BY created_at DESC LIMIT 1`)
	text("last_stream_module", `SELECT COALESCE(module_id,'') FROM security_radar_stream_events ORDER BY created_at DESC LIMIT 1`)
	h.addArvisProcessingMetrics(ctx, metrics)
	count("pump_volume_reports_24h", `SELECT count(*) FROM security_radar_verdicts WHERE module_id='final_verdict_engine' AND signed=true AND source='pump_volume_gate' AND created_at > now()-interval '24 hours'`)
	count("pump_volume_qualified_24h", `SELECT count(DISTINCT target) FROM security_radar_events WHERE event_type='pumpportal_high_volume_24h' AND created_at > now()-interval '24 hours'`)
	text("pump_volume_last_observed_at", `SELECT COALESCE(max(created_at)::text,'') FROM security_radar_events WHERE event_type='pumpportal_high_volume_24h'`)
	metrics["pump_volume_auto_enabled"] = services.PumpHighVolumeRadarEnabled()
	metrics["pump_volume_threshold_usd"] = services.PumpHighVolumeThresholdUSD()
	metrics["pump_volume_window"] = "24h"
	metrics["pump_volume_currency"] = "USD"
	status := arvisPipelineStatus(metrics)
	if services.PumpHighVolumeRadarEnabled() && services.SolanaRPCLimitSaverEnabled() && !services.ForceBackgroundRadarEnabled() {
		status = "selective_auto_volume"
	}
	metrics["pipeline_status"] = status
	return metrics
}

func (h *Handler) addArvisProcessingMetrics(ctx context.Context, metrics map[string]any) {
	if h == nil || h.DBRead == nil || metrics == nil {
		return
	}
	countStatus := func(key, status string) {
		var value int64
		if err := h.DBRead.QueryRowContext(ctx, `SELECT count(*) FROM arvis_stream_processing WHERE status=$1`, status).Scan(&value); err == nil {
			metrics[key] = value
		}
	}
	countQuery := func(key, query string) {
		var value int64
		if err := h.DBRead.QueryRowContext(ctx, query).Scan(&value); err == nil {
			metrics[key] = value
		}
	}
	countStatus("processing_pending", "pending")
	countStatus("processing_active", "processing")
	countStatus("processing_completed", "completed")
	countStatus("processing_insufficient", "insufficient_evidence")
	countStatus("processing_failed", "failed")
	countQuery("processing_completed_recent", `SELECT count(*) FROM arvis_stream_processing WHERE status='completed' AND processed_at > now() - interval '15 minutes'`)
	countQuery("processing_failed_recent", `SELECT count(*) FROM arvis_stream_processing WHERE status='failed' AND updated_at > now() - interval '15 minutes'`)
	countQuery("processing_stale_active", `SELECT count(*) FROM arvis_stream_processing WHERE status='processing' AND updated_at < now() - interval '5 minutes'`)
	var lastProcessed string
	if err := h.DBRead.QueryRowContext(ctx, `SELECT COALESCE(max(processed_at)::text,'') FROM arvis_stream_processing`).Scan(&lastProcessed); err == nil {
		metrics["last_processed_at"] = lastProcessed
	}
}

func arvisPipelineStatus(metrics map[string]any) string {
	raw := metricInt64(metrics, "raw_stream_events")
	if raw == 0 {
		raw = metricInt64(metrics, "sbx1_stream_events")
	}
	active := metricInt64(metrics, "processing_active")
	staleActive := metricInt64(metrics, "processing_stale_active")
	failedRecent := metricInt64(metrics, "processing_failed_recent")
	completedRecent := metricInt64(metrics, "processing_completed_recent")
	if active > 0 && staleActive == 0 {
		return "processing"
	}
	if staleActive > 0 || failedRecent > 0 {
		return "degraded"
	}
	lastEvent := metricTime(metrics, "last_stream_event_at")
	if lastEvent.IsZero() {
		lastEvent = metricTime(metrics, "sbx1_last_event_at")
	}
	if lastEvent.IsZero() {
		if raw > 0 {
			return "waiting_for_enriched_targets"
		}
		return "waiting_for_stream"
	}
	if time.Since(lastEvent) > 10*time.Minute {
		return "stale"
	}
	if metricInt64(metrics, "enriched_mints") == 0 && metricInt64(metrics, "processing_completed") == 0 {
		return "waiting_for_enriched_targets"
	}
	lastProcessed := metricTime(metrics, "last_processed_at")
	if completedRecent > 0 || (!lastProcessed.IsZero() && time.Since(lastProcessed) <= 15*time.Minute) {
		return "healthy"
	}
	return "waiting_for_processing"
}

func metricInt64(metrics map[string]any, key string) int64 {
	if metrics == nil {
		return 0
	}
	switch value := metrics[key].(type) {
	case int64:
		return value
	case int:
		return int64(value)
	case float64:
		return int64(value)
	default:
		return 0
	}
}

func metricTime(metrics map[string]any, key string) time.Time {
	if metrics == nil {
		return time.Time{}
	}
	value := strings.TrimSpace(metricString(metrics, key))
	if value == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999Z07",
		"2006-01-02 15:04:05Z07:00",
		"2006-01-02 15:04:05Z07",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

func metricString(metrics map[string]any, key string) string {
	if metrics == nil {
		return ""
	}
	if value, ok := metrics[key].(string); ok {
		return value
	}
	return ""
}

func radarVerifiedEvidenceSQL() string {
	return `(COALESCE(signals->>'verified_evidence','false')='true' OR COALESCE(signals->>'real_onchain_evidence','false')='true' OR COALESCE(signals->>'real_offchain_evidence','false')='true')`
}

func radarSignalsVerified(signals map[string]any) bool {
	if signals == nil {
		return false
	}
	for _, key := range []string{"verified_evidence", "real_onchain_evidence", "real_offchain_evidence"} {
		if value, _ := signals[key].(bool); value {
			return true
		}
	}
	return false
}

func aggregateSecurityRadarFeedItems(items []services.SecurityRadarVerdictRecord) []securityRadarFeedItem {
	groups := map[string]*securityRadarFeedAccumulator{}
	for _, item := range items {
		key := securityRadarFeedKey(item)
		if key == "" {
			key = strings.TrimSpace(item.ID)
		}
		if key == "" {
			key = strings.TrimSpace(item.Signature)
		}
		if key == "" {
			key = item.CreatedAt.Format(time.RFC3339Nano)
		}
		acc, ok := groups[key]
		if !ok {
			acc = &securityRadarFeedAccumulator{Best: item, MaxRiskIndex: item.RiskIndex, MinRiskIndex: item.RiskIndex, FirstSeenAt: item.CreatedAt, LastSeenAt: item.CreatedAt, RuleVersions: map[string]bool{}, Providers: map[string]bool{}}
			groups[key] = acc
		}
		acc.OccurrenceCount++
		if securityRadarItemIsRisk(item) {
			acc.RiskEvents++
		} else {
			acc.MonitorEvents++
		}
		if item.RiskIndex > acc.MaxRiskIndex {
			acc.MaxRiskIndex = item.RiskIndex
		}
		if item.RiskIndex < acc.MinRiskIndex {
			acc.MinRiskIndex = item.RiskIndex
		}
		if acc.FirstSeenAt.IsZero() || item.CreatedAt.Before(acc.FirstSeenAt) {
			acc.FirstSeenAt = item.CreatedAt
		}
		if item.CreatedAt.After(acc.LastSeenAt) {
			acc.LastSeenAt = item.CreatedAt
		}
		if strings.TrimSpace(item.RuleVersion) != "" {
			acc.RuleVersions[item.RuleVersion] = true
		}
		if strings.TrimSpace(item.Provider) != "" {
			acc.Providers[item.Provider] = true
		}
		if preferSecurityRadarRepresentative(item, acc.Best) {
			acc.Best = item
		}
	}
	out := make([]securityRadarFeedItem, 0, len(groups))
	for _, acc := range groups {
		item := securityRadarFeedItem{SecurityRadarVerdictRecord: acc.Best, OccurrenceCount: acc.OccurrenceCount, RiskEvents: acc.RiskEvents, MonitorEvents: acc.MonitorEvents, MaxRiskIndex: acc.MaxRiskIndex, MinRiskIndex: acc.MinRiskIndex, FirstSeenAt: acc.FirstSeenAt, LastSeenAt: acc.LastSeenAt}
		item.Evidence = enrichSecurityRadarFeedEvidence(item.Evidence, item)
		item.Recommendation = enrichSecurityRadarFeedRecommendation(item.Recommendation, item)
		item.Summary = map[string]any{"deduped": true, "target": item.Target, "network": item.Network, "target_type": item.TargetType, "occurrence_count": item.OccurrenceCount, "risk_events": item.RiskEvents, "monitor_events": item.MonitorEvents, "max_risk_index": item.MaxRiskIndex, "min_risk_index": item.MinRiskIndex, "first_seen_at": item.FirstSeenAt, "last_seen_at": item.LastSeenAt, "rule_versions": keysFromBoolMap(acc.RuleVersions), "providers": keysFromBoolMap(acc.Providers)}
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].MaxRiskIndex != out[j].MaxRiskIndex {
			return out[i].MaxRiskIndex > out[j].MaxRiskIndex
		}
		if out[i].OccurrenceCount != out[j].OccurrenceCount {
			return out[i].OccurrenceCount > out[j].OccurrenceCount
		}
		return out[i].LastSeenAt.After(out[j].LastSeenAt)
	})
	return out
}

func enrichSecurityRadarFeedEvidence(evidence []string, item securityRadarFeedItem) []string {
	out := make([]string, 0, len(evidence)+4)
	if item.OccurrenceCount > 1 {
		out = append(out, "ARVIS feed dedup: bu hedef son radar penceresinde "+strconv.Itoa(item.OccurrenceCount)+" doğrulanmış gözlem altında tek kartta birleştirildi.")
	}
	if item.RiskEvents > 0 || item.MonitorEvents > 0 {
		out = append(out, "Exposure summary: "+strconv.Itoa(item.RiskEvents)+" risk sinyali, "+strconv.Itoa(item.MonitorEvents)+" izleme sinyali aynı hedefe bağlandı.")
	}
	if item.MaxRiskIndex > 0 || item.MinRiskIndex > 0 {
		out = append(out, "Risk range: "+strconv.Itoa(item.MinRiskIndex)+"-"+strconv.Itoa(item.MaxRiskIndex)+"/100; müşteri kartında en güçlü kanıt temsilci karar olarak gösterilir.")
	}
	if !item.LastSeenAt.IsZero() {
		out = append(out, "Last seen: "+item.LastSeenAt.UTC().Format(time.RFC3339)+" UTC canlı ARVIS radarı tarafından gözlendi.")
	}
	out = append(out, evidence...)
	return out
}

func enrichSecurityRadarFeedRecommendation(recommendation string, item securityRadarFeedItem) string {
	recommendation = strings.TrimSpace(recommendation)
	prefix := "ARVIS bu hedefi tekilleştirilmiş exposure kartı olarak gösteriyor: " + strconv.Itoa(item.OccurrenceCount) + " doğrulanmış gözlem, max risk " + strconv.Itoa(item.MaxRiskIndex) + "/100."
	if recommendation == "" {
		return prefix
	}
	return prefix + " " + recommendation
}

func securityRadarFeedKey(item services.SecurityRadarVerdictRecord) string {
	target := strings.ToLower(strings.TrimSpace(item.Target))
	if target == "" {
		return ""
	}
	network := strings.ToLower(strings.TrimSpace(item.Network))
	if network == "" {
		network = "solana-mainnet"
	}
	targetType := strings.ToLower(strings.TrimSpace(item.TargetType))
	return network + "|" + targetType + "|" + target
}

func preferSecurityRadarRepresentative(candidate, current services.SecurityRadarVerdictRecord) bool {
	if candidate.RiskIndex != current.RiskIndex {
		return candidate.RiskIndex > current.RiskIndex
	}
	if securityRadarItemIsRisk(candidate) != securityRadarItemIsRisk(current) {
		return securityRadarItemIsRisk(candidate)
	}
	return candidate.CreatedAt.After(current.CreatedAt)
}

func securityRadarItemIsRisk(item services.SecurityRadarVerdictRecord) bool {
	level := strings.ToLower(strings.TrimSpace(item.RiskLevel))
	if level == "critical" || level == "high" || item.RiskIndex >= 65 {
		return true
	}
	if value, _ := item.Signals["mint_authority_present"].(bool); value {
		return true
	}
	return securityRadarSignalFloat(item.Signals, "top_10_holder_percentage") >= 75
}

func securityRadarSignalFloat(signals map[string]any, key string) float64 {
	if signals == nil {
		return 0
	}
	switch value := signals[key].(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	case json.Number:
		parsed, _ := value.Float64()
		return parsed
	case string:
		parsed, _ := strconv.ParseFloat(strings.TrimSpace(value), 64)
		return parsed
	default:
		return 0
	}
}

func keysFromBoolMap(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func (h *Handler) securityRadarStreamTimeline(ctx context.Context, limit int) []map[string]any {
	out := []map[string]any{}
	if h == nil || h.DBRead == nil {
		return out
	}
	if limit <= 0 || limit > 30 {
		limit = 14
	}
	rows, err := h.DBRead.QueryContext(ctx, `
		SELECT module_id, event_type, COALESCE(target,''), target_type, COALESCE(signature,''), COALESCE(slot,0), COALESCE(program_id,''), evidence_quality, created_at::text
		FROM security_radar_stream_events
		ORDER BY created_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var moduleID, eventType, target, targetType, signature, programID, evidenceQuality, createdAt string
		var slot sql.NullInt64
		if err := rows.Scan(&moduleID, &eventType, &target, &targetType, &signature, &slot, &programID, &evidenceQuality, &createdAt); err != nil {
			continue
		}
		label, meaning := arvisTimelineLabel(moduleID, eventType, evidenceQuality, target)
		out = append(out, map[string]any{"module_id": moduleID, "event_type": eventType, "target": target, "target_type": targetType, "signature": signature, "slot": slot.Int64, "program_id": programID, "evidence_quality": evidenceQuality, "created_at": createdAt, "label": label, "meaning": meaning})
	}
	return out
}

func arvisTimelineLabel(moduleID, eventType, evidenceQuality, target string) (string, string) {
	m := strings.ToLower(moduleID + " " + eventType + " " + evidenceQuality)
	targetLabel := "a Solana event"
	if strings.TrimSpace(target) != "" {
		targetLabel = "target " + shortRadarTarget(target)
	}
	if strings.Contains(m, "raydium") {
		return "Raydium pool activity", "Arvıs detected pool/liquidity-related activity for " + targetLabel + "."
	}
	if strings.Contains(m, "pump") {
		return "Pump.fun launch activity", "Arvıs detected launch/buyer-flow activity for " + targetLabel + "."
	}
	if strings.Contains(m, "mint") || strings.Contains(m, "token") {
		return "Token authority / mint activity", "Arvıs detected token or mint-related activity for " + targetLabel + "."
	}
	if strings.Contains(m, "transaction_enriched") {
		return "Enriched mint resolved", "Arvıs resolved a transaction into a usable mint target."
	}
	return "Raw Solana stream event", "Arvıs captured a live Solana event; it stays internal until enough evidence exists."
}

func shortRadarTarget(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 18 {
		return v
	}
	return v[:8] + "…" + v[len(v)-6:]
}

func streamEnvEnabled() bool {
	v := strings.TrimSpace(firstNonEmptyString(os.Getenv("RADAR_STREAM_ENABLED"), os.Getenv("KOSCHEI_AUTO_RADAR_ENABLED")))
	return strings.EqualFold(v, "1") || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") || strings.EqualFold(v, "on") || strings.EqualFold(strings.TrimSpace(os.Getenv("KOSCHEI_SOLANA_WATCH_MODE")), "stream")
}

func streamWSSConfigured() bool {
	return strings.TrimSpace(firstNonEmptyString(os.Getenv("SOLANA_WSS_URL"), os.Getenv("ALCHEMY_SOLANA_WSS_URL"), os.Getenv("HELIUS_SOLANA_WSS_URL"), os.Getenv("QUICKNODE_SOLANA_WSS_URL"), os.Getenv("PUMPPORTAL_DATA_WS"), os.Getenv("ALCHEMY_API_KEY"))) != ""
}

func (h *Handler) saveSecurityRadarBundle(ctx context.Context, userID, source string, bundle services.SecurityRadarBundle) error {
	if h == nil || h.DB == nil || !services.SecurityRadarHasLiveEvidence(bundle) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	verdicts := services.ArvisArmsFromBundle(bundle)
	if len(verdicts) == 0 {
		verdicts = []services.SecurityRadarVerdict{bundle.PumpSybilRadar, bundle.RaydiumPoolGuardian, bundle.WalletlessClaimShield}
	}
	for _, verdict := range verdicts {
		if !services.SecurityRadarVerdictHasVerifiedEvidence(verdict) {
			continue
		}
		if err := h.saveSecurityRadarVerdict(ctx, userID, source, verdict); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) saveSecurityRadarVerdict(ctx context.Context, userID, source string, verdict services.SecurityRadarVerdict) error {
	if !services.SecurityRadarVerdictHasVerifiedEvidence(verdict) {
		return nil
	}
	targetType := "token"
	if onchain, _ := verdict.Signals["real_onchain_evidence"].(bool); !onchain {
		if offchain, _ := verdict.Signals["real_offchain_evidence"].(bool); offchain {
			targetType = "url"
		}
	}
	store := services.NewSecurityRadarStore(h.DB)
	eventID, err := store.InsertEvent(ctx, services.SecurityRadarEventRecord{ModuleID: verdict.ModuleID, Target: verdict.Target, TargetType: targetType, Network: verdict.Network, Signature: verdict.Signature, EventType: firstNonEmptyString(source, "manual_verdict"), Signals: verdict.Signals, RawSummary: map[string]any{"source": source, "user_id": userID}, Source: firstNonEmptyString(source, "manual_check")})
	if err != nil {
		return err
	}
	_, err = store.InsertVerdict(ctx, services.SecurityRadarVerdictRecord{EventID: eventID, ModuleID: verdict.ModuleID, Target: verdict.Target, TargetType: targetType, Network: verdict.Network, Grade: verdict.Grade, RiskIndex: verdict.RiskIndex, RiskLevel: verdict.RiskLevel, Verdict: verdict.Verdict, Recommendation: verdict.Recommendation, Evidence: verdict.Evidence, Signals: verdict.Signals, RuleVersion: verdict.RuleVersion, Signed: verdict.Signed, Signature: verdict.Signature, Source: firstNonEmptyString(source, "manual_check")})
	return err
}

func jsonRaw(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return string(raw)
	}
	return value
}
