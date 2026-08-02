package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"sort"
	"strings"

	"koschei/api/internal/alerts"
)

type securityAlertWebhookSubscriptionRequest struct {
	EndpointID string   `json:"endpoint_id"`
	Enabled    *bool    `json:"enabled,omitempty"`
	EventTypes []string `json:"event_types,omitempty"`
}

var supportedSecurityAlertEvents = map[string]bool{
	alerts.EventSecurityAlertCreated:     true,
	alerts.EventARVISVerdictCreated:      true,
	alerts.EventTransactionGuardDecision: true,
}

type securityAlertSubscriptionQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (h *Handler) SecurityAlertWebhookSubscription(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if h == nil || h.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database_unavailable"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		endpointID := strings.TrimSpace(r.URL.Query().Get("endpoint_id"))
		h.writeSecurityAlertWebhookSubscription(w, r, claims.Sub, endpointID)
	case http.MethodPost:
		var input securityAlertWebhookSubscriptionRequest
		if err := decodeJSON(r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
			return
		}
		input.EndpointID = strings.TrimSpace(input.EndpointID)
		if !webhookUUIDPattern.MatchString(input.EndpointID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_webhook_id"})
			return
		}
		events, err := normalizeSecurityAlertEvents(input.EventTypes)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		enabled := true
		if input.Enabled != nil {
			enabled = *input.Enabled
		}

		tx, err := h.DB.BeginTx(r.Context(), nil)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
			return
		}
		defer tx.Rollback()
		var endpointExists bool
		if err := tx.QueryRowContext(r.Context(), `
			SELECT EXISTS(SELECT 1 FROM webhook_endpoints WHERE id=$1 AND auth_subject=$2)`, input.EndpointID, claims.Sub).Scan(&endpointExists); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
			return
		}
		if !endpointExists {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "webhook_not_found"})
			return
		}
		for _, eventType := range events {
			if enabled {
				if _, err := tx.ExecContext(r.Context(), `
					INSERT INTO security_alert_webhook_subscriptions (endpoint_id,auth_subject,event_type)
					VALUES ($1,$2,$3) ON CONFLICT (endpoint_id,event_type) DO NOTHING`, input.EndpointID, claims.Sub, eventType); err != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
					return
				}
			} else if _, err := tx.ExecContext(r.Context(), `
				DELETE FROM security_alert_webhook_subscriptions
				WHERE endpoint_id=$1 AND auth_subject=$2 AND event_type=$3`, input.EndpointID, claims.Sub, eventType); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
				return
			}
		}
		selected, err := loadSecurityAlertSubscriptions(r.Context(), tx, input.EndpointID, claims.Sub)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
			return
		}
		if err := tx.Commit(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "endpoint_id": input.EndpointID, "enabled": enabled, "security_event_types": selected, "supported_security_event_types": sortedSupportedSecurityAlertEvents()})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) writeSecurityAlertWebhookSubscription(w http.ResponseWriter, r *http.Request, authSubject, endpointID string) {
	if !webhookUUIDPattern.MatchString(endpointID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_webhook_id"})
		return
	}
	var endpointExists bool
	if err := h.DB.QueryRowContext(r.Context(), `
		SELECT EXISTS(SELECT 1 FROM webhook_endpoints WHERE id=$1 AND auth_subject=$2)`, endpointID, authSubject).Scan(&endpointExists); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	if !endpointExists {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "webhook_not_found"})
		return
	}
	selected, err := loadSecurityAlertSubscriptions(r.Context(), h.DB, endpointID, authSubject)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "endpoint_id": endpointID, "security_event_types": selected, "supported_security_event_types": sortedSupportedSecurityAlertEvents()})
}

func loadSecurityAlertSubscriptions(ctx context.Context, queryer securityAlertSubscriptionQueryer, endpointID, authSubject string) ([]string, error) {
	rows, err := queryer.QueryContext(ctx, `
		SELECT event_type FROM security_alert_webhook_subscriptions
		WHERE endpoint_id=$1 AND auth_subject=$2 ORDER BY event_type`, endpointID, authSubject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var eventType string
		if err := rows.Scan(&eventType); err != nil {
			return nil, err
		}
		out = append(out, eventType)
	}
	return out, rows.Err()
}

func normalizeSecurityAlertEvents(input []string) ([]string, error) {
	if len(input) == 0 {
		return []string{alerts.EventSecurityAlertCreated}, nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range input {
		value := strings.ToLower(strings.TrimSpace(raw))
		if !supportedSecurityAlertEvents[value] {
			return nil, errors.New("unsupported_security_event_type")
		}
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out, nil
}

func sortedSupportedSecurityAlertEvents() []string {
	out := make([]string, 0, len(supportedSecurityAlertEvents))
	for eventType := range supportedSecurityAlertEvents {
		out = append(out, eventType)
	}
	sort.Strings(out)
	return out
}
