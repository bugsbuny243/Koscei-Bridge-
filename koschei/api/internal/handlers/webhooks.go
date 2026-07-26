package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/webhooks"
	"koschei/api/internal/workerwake"
)

const webhookEndpointLimit = 10

var webhookUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

type webhookEndpointRequest struct {
	Name       string   `json:"name"`
	URL        string   `json:"url"`
	Status     string   `json:"status"`
	EventTypes []string `json:"event_types"`
}

type webhookEndpoint struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	URL            string     `json:"url"`
	SecretLast4    string     `json:"secret_last4"`
	Status         string     `json:"status"`
	EventTypes     []string   `json:"event_types"`
	FailureCount   int        `json:"failure_count"`
	LastDeliveryAt *time.Time `json:"last_delivery_at"`
	LastSuccessAt  *time.Time `json:"last_success_at"`
	LastFailureAt  *time.Time `json:"last_failure_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type webhookDelivery struct {
	ID              string         `json:"id"`
	EndpointID      string         `json:"endpoint_id"`
	EndpointName    string         `json:"endpoint_name"`
	EventID         *string        `json:"event_id"`
	EventType       string         `json:"event_type"`
	Payload         map[string]any `json:"payload"`
	Status          string         `json:"status"`
	AttemptCount    int            `json:"attempt_count"`
	MaxAttempts     int            `json:"max_attempts"`
	NextAttemptAt   time.Time      `json:"next_attempt_at"`
	LastHTTPStatus  *int           `json:"last_http_status"`
	LastError       string         `json:"last_error,omitempty"`
	ResponseExcerpt string         `json:"response_excerpt,omitempty"`
	DeliveredAt     *time.Time     `json:"delivered_at"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

func (h *Handler) WebhookEndpoints(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listWebhookEndpoints(w, r)
	case http.MethodPost:
		h.createWebhookEndpoint(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) WebhookEndpointItem(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/webhooks/"), "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || !webhookUUIDPattern.MatchString(parts[0]) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_webhook_id"})
		return
	}
	id := parts[0]
	if len(parts) == 2 {
		switch parts[1] {
		case "rotate-secret":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			h.rotateWebhookSecret(w, r, id)
			return
		case "test":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			h.enqueueWebhookTest(w, r, id)
			return
		}
	}
	if len(parts) != 1 {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPatch:
		h.updateWebhookEndpoint(w, r, id)
	case http.MethodDelete:
		h.deleteWebhookEndpoint(w, r, id)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) WebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 250 {
			limit = parsed
		}
	}
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	if status != "" && !validDeliveryStatus(status) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_delivery_status"})
		return
	}
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT d.id::text,d.endpoint_id::text,e.name,d.event_id::text,d.event_type,d.payload,d.status,
		       d.attempt_count,d.max_attempts,d.next_attempt_at,d.last_http_status,COALESCE(d.last_error,''),
		       COALESCE(d.response_excerpt,''),d.delivered_at,d.created_at,d.updated_at
		FROM webhook_deliveries d
		JOIN webhook_endpoints e ON e.id=d.endpoint_id
		WHERE d.auth_subject=$1 AND ($2='' OR d.status=$2)
		ORDER BY d.created_at DESC
		LIMIT $3`, claims.Sub, status, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	defer rows.Close()
	items := []webhookDelivery{}
	for rows.Next() {
		var item webhookDelivery
		var eventID sql.NullString
		var payloadRaw []byte
		var httpStatus sql.NullInt64
		var deliveredAt sql.NullTime
		if err := rows.Scan(&item.ID, &item.EndpointID, &item.EndpointName, &eventID, &item.EventType, &payloadRaw, &item.Status,
			&item.AttemptCount, &item.MaxAttempts, &item.NextAttemptAt, &httpStatus, &item.LastError,
			&item.ResponseExcerpt, &deliveredAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
			return
		}
		if eventID.Valid {
			value := eventID.String
			item.EventID = &value
		}
		if httpStatus.Valid {
			value := int(httpStatus.Int64)
			item.LastHTTPStatus = &value
		}
		if deliveredAt.Valid {
			value := deliveredAt.Time
			item.DeliveredAt = &value
		}
		item.Payload = decodeJSONMap(payloadRaw)
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deliveries": items})
}

func (h *Handler) WebhookDeliveryItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/webhooks/deliveries/"), "/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[1] != "retry" || !webhookUUIDPattern.MatchString(parts[0]) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_delivery_id"})
		return
	}
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	res, err := h.DB.ExecContext(r.Context(), `
		UPDATE webhook_deliveries
		SET status='retry',next_attempt_at=now(),locked_at=NULL,last_error=NULL,updated_at=now()
		WHERE id=$1 AND auth_subject=$2 AND status IN ('dead_letter','retry')`, parts[0], claims.Sub)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	count, _ := res.RowsAffected()
	if count == 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "delivery_not_retryable"})
		return
	}
	workerwake.Signal(workerwake.WebhookDelivery)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "delivery_id": parts[0]})
}

func (h *Handler) listWebhookEndpoints(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT id::text,name,url,secret_last4,status,event_types,failure_count,last_delivery_at,last_success_at,
		       last_failure_at,created_at,updated_at
		FROM webhook_endpoints
		WHERE auth_subject=$1
		ORDER BY updated_at DESC`, claims.Sub)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	defer rows.Close()
	items := []webhookEndpoint{}
	for rows.Next() {
		item, scanErr := scanWebhookEndpoint(rows)
		if scanErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
			return
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "endpoints": items, "max_endpoints": webhookEndpointLimit})
}

func (h *Handler) createWebhookEndpoint(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req webhookEndpointRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.URL = strings.TrimSpace(req.URL)
	if req.Name == "" || len(req.Name) > 80 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_name"})
		return
	}
	parsed, err := webhooks.ValidateEndpointURL(r.Context(), req.URL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_or_unsafe_webhook_url"})
		return
	}
	events, err := normalizeWebhookEvents(req.EventTypes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var count int
	if err := h.DB.QueryRowContext(r.Context(), `SELECT count(*) FROM webhook_endpoints WHERE auth_subject=$1`, claims.Sub).Scan(&count); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	if count >= webhookEndpointLimit {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "webhook_limit_reached", "max_endpoints": webhookEndpointLimit})
		return
	}
	secret, err := webhooks.GenerateSecret()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "secret_generation_failed"})
		return
	}
	ciphertext, err := webhooks.EncryptSecret(secret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "secret_encryption_failed"})
		return
	}
	var id string
	err = h.DB.QueryRowContext(r.Context(), `
		INSERT INTO webhook_endpoints (auth_subject,name,url,secret_ciphertext,secret_last4,event_types)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id::text`, claims.Sub, req.Name, parsed.String(), ciphertext, webhooks.Last4(secret), stringSliceToPGArray(events)).Scan(&id)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "webhook_name_exists"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":            true,
		"endpoint":      map[string]any{"id": id, "name": req.Name, "url": parsed.String(), "status": "active", "event_types": events, "secret_last4": webhooks.Last4(secret)},
		"secret":        secret,
		"secret_notice": "This secret is shown once. Store it securely before leaving this page.",
	})
}

func (h *Handler) updateWebhookEndpoint(w http.ResponseWriter, r *http.Request, id string) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req webhookEndpointRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	var name, endpointURL, status any
	if strings.TrimSpace(req.Name) != "" {
		trimmed := strings.TrimSpace(req.Name)
		if len(trimmed) > 80 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_name"})
			return
		}
		name = trimmed
	}
	if strings.TrimSpace(req.URL) != "" {
		parsed, err := webhooks.ValidateEndpointURL(r.Context(), req.URL)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_or_unsafe_webhook_url"})
			return
		}
		endpointURL = parsed.String()
	}
	if strings.TrimSpace(req.Status) != "" {
		value := strings.ToLower(strings.TrimSpace(req.Status))
		if value != "active" && value != "paused" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_status"})
			return
		}
		status = value
	}
	var events any
	if req.EventTypes != nil {
		normalized, err := normalizeWebhookEvents(req.EventTypes)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		events = stringSliceToPGArray(normalized)
	}
	res, err := h.DB.ExecContext(r.Context(), `
		UPDATE webhook_endpoints
		SET name=COALESCE($1,name),url=COALESCE($2,url),status=COALESCE($3,status),event_types=COALESCE($4,event_types),
		    failure_count=CASE WHEN COALESCE($3,status)='active' THEN 0 ELSE failure_count END,updated_at=now()
		WHERE id=$5 AND auth_subject=$6`, name, endpointURL, status, events, id, claims.Sub)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	count, _ := res.RowsAffected()
	if count == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "webhook_not_found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) deleteWebhookEndpoint(w http.ResponseWriter, r *http.Request, id string) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM webhook_endpoints WHERE id=$1 AND auth_subject=$2`, id, claims.Sub)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	count, _ := res.RowsAffected()
	if count == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "webhook_not_found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": id})
}

func (h *Handler) rotateWebhookSecret(w http.ResponseWriter, r *http.Request, id string) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	secret, err := webhooks.GenerateSecret()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "secret_generation_failed"})
		return
	}
	ciphertext, err := webhooks.EncryptSecret(secret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "secret_encryption_failed"})
		return
	}
	res, err := h.DB.ExecContext(r.Context(), `
		UPDATE webhook_endpoints SET secret_ciphertext=$1,secret_last4=$2,failure_count=0,updated_at=now()
		WHERE id=$3 AND auth_subject=$4`, ciphertext, webhooks.Last4(secret), id, claims.Sub)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	count, _ := res.RowsAffected()
	if count == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "webhook_not_found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "secret": secret, "secret_last4": webhooks.Last4(secret), "secret_notice": "This secret is shown once."})
}

func (h *Handler) enqueueWebhookTest(w http.ResponseWriter, r *http.Request, id string) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	payload, _ := json.Marshal(map[string]any{
		"id": newID(), "type": "webhook.test", "created_at": time.Now().UTC().Format(time.RFC3339),
		"data": map[string]any{"message": "Koschei webhook delivery test", "endpoint_id": id},
	})
	var deliveryID string
	err := h.DB.QueryRowContext(r.Context(), `
		INSERT INTO webhook_deliveries (endpoint_id,auth_subject,event_type,payload)
		SELECT id,auth_subject,'webhook.test',$1::jsonb FROM webhook_endpoints
		WHERE id=$2 AND auth_subject=$3 AND status='active'
		RETURNING id::text`, string(payload), id, claims.Sub).Scan(&deliveryID)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "webhook_not_found_or_paused"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	// Wake the delivery worker immediately (#697): the worker is idle-blocked
	// rather than polling, so enqueue paths must announce new work.
	workerwake.Signal(workerwake.WebhookDelivery)
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "delivery_id": deliveryID, "status": "pending"})
}

func enqueueWatchlistWebhookDeliveries(ctx context.Context, tx *sql.Tx, authSubject, alertID string, target watchlistTarget, alert watchlistAlertCandidate) error {
	payload, err := json.Marshal(map[string]any{
		"id":         alertID,
		"type":       "watchlist.alert.created",
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"data": map[string]any{
			"watchlist_id":   target.ID,
			"target":         target.Target,
			"target_type":    target.TargetType,
			"network":        target.Network,
			"label":          target.Label,
			"event_type":     alert.EventType,
			"severity":       alert.Severity,
			"title":          alert.Title,
			"message":        alert.Message,
			"previous_value": alert.PreviousValue,
			"current_value":  alert.CurrentValue,
			"evidence":       alert.Evidence,
		},
	})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO webhook_deliveries (endpoint_id,auth_subject,event_id,event_type,payload)
		SELECT id,auth_subject,$2::uuid,'watchlist.alert.created',$3::jsonb
		FROM webhook_endpoints
		WHERE auth_subject=$1 AND status='active' AND 'watchlist.alert.created'=ANY(event_types)
		ON CONFLICT (endpoint_id,event_id,event_type) DO NOTHING`, authSubject, alertID, string(payload))
	return err
}

func scanWebhookEndpoint(rows *sql.Rows) (webhookEndpoint, error) {
	var item webhookEndpoint
	var eventTypes []byte
	var lastDelivery, lastSuccess, lastFailure sql.NullTime
	err := rows.Scan(&item.ID, &item.Name, &item.URL, &item.SecretLast4, &item.Status, &eventTypes, &item.FailureCount,
		&lastDelivery, &lastSuccess, &lastFailure, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return item, err
	}
	item.EventTypes = parsePGTextArray(string(eventTypes))
	if lastDelivery.Valid {
		value := lastDelivery.Time
		item.LastDeliveryAt = &value
	}
	if lastSuccess.Valid {
		value := lastSuccess.Time
		item.LastSuccessAt = &value
	}
	if lastFailure.Valid {
		value := lastFailure.Time
		item.LastFailureAt = &value
	}
	return item, nil
}

func normalizeWebhookEvents(input []string) ([]string, error) {
	if input == nil || len(input) == 0 {
		return []string{"watchlist.alert.created"}, nil
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, raw := range input {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value != "watchlist.alert.created" {
			return nil, errors.New("unsupported_event_type")
		}
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out, nil
}

func validDeliveryStatus(value string) bool {
	switch value {
	case "pending", "processing", "retry", "delivered", "dead_letter":
		return true
	default:
		return false
	}
}

func stringSliceToPGArray(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ReplaceAll(value, `\`, `\\`)
		value = strings.ReplaceAll(value, `"`, `\"`)
		quoted = append(quoted, `"`+value+`"`)
	}
	return `{` + strings.Join(quoted, ",") + `}`
}

func parsePGTextArray(value string) []string {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != '{' || value[len(value)-1] != '}' {
		return []string{}
	}
	value = strings.Trim(value, "{}")
	if value == "" {
		return []string{}
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, strings.Trim(strings.TrimSpace(part), `"`))
	}
	return out
}
