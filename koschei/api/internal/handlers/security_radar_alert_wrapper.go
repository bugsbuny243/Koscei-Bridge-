package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"koschei/api/internal/alerts"
)

const maxSecurityRadarAlertBody = 1 << 20

// SecurityRadarCheckWithAlerts preserves the existing investigation response
// contract and adds a durable alert only after a signed, evidence-ready verdict
// has been produced. The alert pipeline never changes the deterministic grade.
func (h *Handler) SecurityRadarCheckWithAlerts(w http.ResponseWriter, r *http.Request) {
	rawBody, err := io.ReadAll(io.LimitReader(r.Body, maxSecurityRadarAlertBody+1))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Invalid request body")
		return
	}
	if len(rawBody) > maxSecurityRadarAlertBody {
		writeAPIError(w, http.StatusRequestEntityTooLarge, APICodeInvalidInput, "Request body is too large")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(rawBody))

	var input securityRadarInput
	_ = json.Unmarshal(rawBody, &input)
	target := strings.TrimSpace(firstNonEmptyString(input.Target, input.Address))

	recorder := httptest.NewRecorder()
	h.SecurityRadarCheck(recorder, r)
	result := recorder.Result()
	defer result.Body.Close()
	responseBody, _ := io.ReadAll(result.Body)

	alertID := ""
	if result.StatusCode >= 200 && result.StatusCode < 300 && h != nil && h.DB != nil {
		var envelope map[string]any
		if json.Unmarshal(responseBody, &envelope) == nil {
			alertID = h.emitARVISVerdictAlert(r, target, envelope)
			if alertID != "" {
				envelope["alert_event_id"] = alertID
				if encoded, marshalErr := json.Marshal(envelope); marshalErr == nil {
					responseBody = encoded
				}
			}
		}
	}

	for key, values := range result.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.Header().Del("Content-Length")
	w.WriteHeader(result.StatusCode)
	_, _ = w.Write(responseBody)
}

func (h *Handler) emitARVISVerdictAlert(r *http.Request, target string, envelope map[string]any) string {
	if r == nil || h == nil || h.DB == nil {
		return ""
	}
	status := strings.ToLower(strings.TrimSpace(stringFromMap(envelope, "status")))
	hasEvidence, _ := envelope["has_live_evidence"].(bool)
	final, _ := envelope["final_verdict"].(map[string]any)
	if status != "ready" || !hasEvidence || final == nil {
		return ""
	}
	signed, _ := final["signed"].(bool)
	if !signed {
		return ""
	}
	riskLevel := strings.ToLower(strings.TrimSpace(stringFromMap(final, "risk_level")))
	if riskLevel != "medium" && riskLevel != "high" && riskLevel != "critical" {
		return ""
	}
	signature := strings.TrimSpace(stringFromMap(final, "signature"))
	if signature == "" {
		return ""
	}
	grade := strings.TrimSpace(stringFromMap(final, "grade"))
	ruleVersion := strings.TrimSpace(stringFromMap(final, "rule_version"))
	verdict := strings.TrimSpace(stringFromMap(final, "verdict"))
	recommendation := strings.TrimSpace(stringFromMap(final, "recommendation"))
	claims, _ := userFromContext(r.Context())
	if target == "" {
		target = strings.TrimSpace(stringFromMap(envelope, "target"))
	}
	message := verdict
	if message == "" {
		message = "ARVIS produced a signed " + riskLevel + "-risk verdict."
	}
	id, err := alerts.Emit(r.Context(), h.DB, alerts.Event{
		AuthSubject: claims.Sub,
		Source:      "arvis",
		EventType:   alerts.EventARVISVerdictCreated,
		Severity:    riskLevel,
		Target:      target,
		Title:       "ARVIS signed verdict: " + strings.ToUpper(riskLevel),
		Message:     message,
		DedupeKey:   arvisAlertDedupeKey(claims.Sub, signature),
		EvidenceRef: signature,
		Payload:     arvisAlertPayload(target, grade, riskLevel, recommendation, signature, ruleVersion),
	})
	if err != nil {
		return ""
	}
	return id
}

func arvisAlertDedupeKey(authSubject, signature string) string {
	scope := strings.TrimSpace(authSubject)
	if scope == "" {
		scope = "unscoped"
	}
	return "arvis-verdict:" + scope + ":" + strings.TrimSpace(signature)
}

func arvisAlertPayload(target, grade, riskLevel, recommendation, signature, ruleVersion string) map[string]any {
	return map[string]any{
		"target":         target,
		"grade":          grade,
		"risk_level":     riskLevel,
		"recommendation": recommendation,
		"signature":      signature,
		"rule_version":   ruleVersion,
	}
}

func stringFromMap(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value, _ := values[key].(string)
	return value
}
