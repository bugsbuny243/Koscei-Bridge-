package alerts

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"koschei/api/internal/workerwake"
)

const (
	EventSecurityAlertCreated      = "security.alert.created"
	EventARVISVerdictCreated       = "arvis.verdict.created"
	EventTransactionGuardDecision = "transaction.guard.decision"
)

type Event struct {
	AuthSubject string         `json:"auth_subject,omitempty"`
	Source      string         `json:"source"`
	EventType   string         `json:"event_type"`
	Severity    string         `json:"severity"`
	Target      string         `json:"target,omitempty"`
	Title       string         `json:"title"`
	Message     string         `json:"message"`
	DedupeKey   string         `json:"dedupe_key,omitempty"`
	EvidenceRef string         `json:"evidence_ref,omitempty"`
	Payload     map[string]any `json:"payload,omitempty"`
	CreatedAt   time.Time      `json:"created_at,omitempty"`
}

func Emit(ctx context.Context, db *sql.DB, event Event) (string, error) {
	if db == nil {
		return "", fmt.Errorf("security alert database is unavailable")
	}
	event = normalizeEvent(event)
	if event.Source == "" || event.EventType == "" || event.Title == "" {
		return "", fmt.Errorf("security alert source, event type and title are required")
	}
	payload := clonePayload(event.Payload)
	if event.EvidenceRef != "" {
		payload["evidence_ref"] = event.EvidenceRef
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode security alert payload: %w", err)
	}

	var id string
	err = db.QueryRowContext(ctx, `
		INSERT INTO security_alert_events
		(auth_subject,source,event_type,severity,target,title,message,dedupe_key,payload,created_at,last_seen_at)
		VALUES (NULLIF($1,''),$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$10)
		ON CONFLICT (dedupe_key) DO UPDATE
		SET occurrence_count=security_alert_events.occurrence_count+1,
		    last_seen_at=EXCLUDED.last_seen_at,
		    payload=EXCLUDED.payload,
		    message=EXCLUDED.message,
		    severity=CASE
		      WHEN security_alert_severity_rank(EXCLUDED.severity) > security_alert_severity_rank(security_alert_events.severity)
		      THEN EXCLUDED.severity ELSE security_alert_events.severity END
		RETURNING id::text`, event.AuthSubject, event.Source, event.EventType, event.Severity, event.Target,
		event.Title, event.Message, event.DedupeKey, string(payloadJSON), event.CreatedAt).Scan(&id)
	if err != nil {
		return "", err
	}

	queued := false
	if shouldQueueSystemChannels(event.Severity) {
		if telegramConfigured() {
			queued = insertSystemDelivery(ctx, db, id, "telegram") || queued
		}
		if discordConfigured() {
			queued = insertSystemDelivery(ctx, db, id, "discord") || queued
		}
	}
	if queued {
		workerwake.Signal(workerwake.SecurityAlertDelivery)
	}
	return id, nil
}

func insertSystemDelivery(ctx context.Context, db *sql.DB, alertID, channel string) bool {
	result, err := db.ExecContext(ctx, `
		INSERT INTO security_alert_deliveries (alert_id,channel)
		VALUES ($1,$2) ON CONFLICT (alert_id,channel) DO NOTHING`, alertID, channel)
	if err != nil {
		return false
	}
	rows, err := result.RowsAffected()
	return err == nil && rows > 0
}

func normalizeEvent(event Event) Event {
	event.AuthSubject = strings.TrimSpace(event.AuthSubject)
	event.Source = truncate(strings.TrimSpace(event.Source), 80)
	event.EventType = truncate(strings.ToLower(strings.TrimSpace(event.EventType)), 120)
	event.Severity = normalizeSeverity(event.Severity)
	event.Target = truncate(strings.TrimSpace(event.Target), 256)
	event.Title = truncate(strings.TrimSpace(event.Title), 240)
	event.Message = truncate(strings.TrimSpace(event.Message), 4000)
	event.EvidenceRef = truncate(strings.TrimSpace(event.EvidenceRef), 256)
	if event.Message == "" {
		event.Message = event.Title
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	} else {
		event.CreatedAt = event.CreatedAt.UTC()
	}
	if strings.TrimSpace(event.DedupeKey) == "" {
		event.DedupeKey = defaultDedupeKey(event)
	} else {
		event.DedupeKey = scopedCustomDedupeKey(event.AuthSubject, event.DedupeKey)
	}
	return event
}

func defaultDedupeKey(event Event) string {
	material := strings.Join([]string{event.AuthSubject, event.Source, event.EventType, event.Target, event.Severity, event.Title, event.EvidenceRef}, "\n")
	sum := sha256.Sum256([]byte(material))
	return "alert:" + hex.EncodeToString(sum[:])
}

// scopedCustomDedupeKey prevents a caller-supplied key from colliding across
// customer tenants. System events without an auth subject keep their explicit
// key so operator-controlled global deduplication remains available.
func scopedCustomDedupeKey(authSubject, key string) string {
	key = truncate(strings.TrimSpace(key), 256)
	authSubject = strings.TrimSpace(authSubject)
	if authSubject == "" {
		return key
	}
	material := authSubject + "\n" + key
	sum := sha256.Sum256([]byte(material))
	return "tenant-alert:" + hex.EncodeToString(sum[:])
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "warning", "warn":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

func severityRank(value string) int {
	switch normalizeSeverity(value) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func shouldQueueSystemChannels(severity string) bool {
	minimum := normalizeSeverity(os.Getenv("SECURITY_ALERT_MIN_SEVERITY"))
	if strings.TrimSpace(os.Getenv("SECURITY_ALERT_MIN_SEVERITY")) == "" {
		minimum = "high"
	}
	return severityRank(severity) >= severityRank(minimum)
}

func telegramConfigured() bool {
	return strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN")) != "" && strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID")) != ""
}

func discordConfigured() bool {
	return strings.TrimSpace(os.Getenv("DISCORD_WEBHOOK_URL")) != ""
}

func clonePayload(input map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range input {
		out[key] = value
	}
	return out
}

func truncate(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}
