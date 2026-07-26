package webhooks

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"koschei/api/internal/workerwake"
)

const (
	deliveryBatchSize = 10
	// deliveryErrorBackoff is the retry delay after a failed claim: short enough
	// that a pending delivery is not stranded, long enough to avoid a hot loop.
	deliveryErrorBackoff = 5 * time.Second
	maxResponseBytes     = 32 << 10
)

type deliveryRecord struct {
	ID               string
	EndpointID       string
	URL              string
	SecretCiphertext string
	EventID          sql.NullString
	EventType        string
	Payload          []byte
	AttemptCount     int
	MaxAttempts      int
}

func StartDeliveryWorker(parent context.Context, db *sql.DB) func() {
	if db == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(parent)
	client := NewDeliveryClient()
	var once sync.Once
	go func() {
		if transport, ok := client.Transport.(*http.Transport); ok {
			defer transport.CloseIdleConnections()
		}
		_, _ = db.ExecContext(ctx, `
			UPDATE webhook_deliveries
			SET status='retry', locked_at=NULL, next_attempt_at=now(), updated_at=now(),
			    last_error=COALESCE(last_error,'delivery worker recovered stale lock')
			WHERE status='processing' AND locked_at < now()-interval '2 minutes'`)
		gate := workerwake.Get(workerwake.WebhookDelivery)
		log.Printf("webhook delivery worker started mode=event-driven recovery-ceiling=%s", workerwake.RecoveryCeiling())
		for {
			if ctx.Err() != nil {
				return
			}
			gate.Drain()
			processed, err := processDeliveryBatch(ctx, db, client)
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("webhook delivery worker: %v", err)
				}
				// A claim failure is not an empty queue. Back off briefly rather
				// than re-deriving a due time and spinning against a database that
				// is failing, waking or degraded.
				gate.Wait(ctx, deliveryErrorBackoff)
				continue
			}
			// A full batch means the queue is still backed up: continue draining
			// without sleeping. Anything less means the queue is empty or the
			// remaining rows are scheduled for later.
			if processed >= deliveryBatchSize {
				continue
			}
			sleep := workerwake.NextDueSleep(ctx, db, workerwake.WebhookDelivery)
			if sleep <= 0 {
				continue
			}
			gate.Wait(ctx, sleep)
		}
	}()
	return func() { once.Do(cancel) }
}

// processDeliveryBatch claims and delivers up to deliveryBatchSize rows and
// reports how many it processed, so the caller can distinguish "queue drained"
// from "batch limit reached".
func processDeliveryBatch(ctx context.Context, db *sql.DB, client *http.Client) (int, error) {
	processed := 0
	for i := 0; i < deliveryBatchSize; i++ {
		delivery, err := claimDelivery(ctx, db)
		if err == sql.ErrNoRows {
			return processed, nil
		}
		if err != nil {
			return processed, err
		}
		processDelivery(ctx, db, client, delivery)
		processed++
	}
	return processed, nil
}

func claimDelivery(ctx context.Context, db *sql.DB) (deliveryRecord, error) {
	var item deliveryRecord
	err := db.QueryRowContext(ctx, `
		WITH candidate AS (
			SELECT d.id
			FROM webhook_deliveries d
			JOIN webhook_endpoints e ON e.id=d.endpoint_id
			WHERE d.status IN ('pending','retry')
			  AND d.next_attempt_at <= now()
			  AND e.status='active'
			ORDER BY d.next_attempt_at ASC,d.created_at ASC
			FOR UPDATE OF d SKIP LOCKED
			LIMIT 1
		)
		UPDATE webhook_deliveries d
		SET status='processing',attempt_count=d.attempt_count+1,locked_at=now(),updated_at=now()
		FROM candidate c,webhook_endpoints e
		WHERE d.id=c.id AND e.id=d.endpoint_id
		RETURNING d.id::text,d.endpoint_id::text,e.url,e.secret_ciphertext,d.event_id::text,
		          d.event_type,d.payload,d.attempt_count,d.max_attempts`).
		Scan(&item.ID, &item.EndpointID, &item.URL, &item.SecretCiphertext, &item.EventID,
			&item.EventType, &item.Payload, &item.AttemptCount, &item.MaxAttempts)
	return item, err
}

func processDelivery(ctx context.Context, db *sql.DB, client *http.Client, item deliveryRecord) {
	deliveryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	parsed, err := ValidateEndpointURL(deliveryCtx, item.URL)
	if err != nil {
		markDeliveryFailure(ctx, db, item, 0, err.Error(), "", false)
		return
	}
	secret, err := DecryptSecret(item.SecretCiphertext)
	if err != nil {
		markDeliveryFailure(ctx, db, item, 0, "webhook secret decrypt failed", "", false)
		return
	}
	payload := compactJSON(item.Payload)
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	req, err := http.NewRequestWithContext(deliveryCtx, http.MethodPost, parsed.String(), bytes.NewReader(payload))
	if err != nil {
		markDeliveryFailure(ctx, db, item, 0, err.Error(), "", false)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Koschei-Webhook/1.0")
	req.Header.Set("X-Koschei-Delivery-ID", item.ID)
	req.Header.Set("X-Koschei-Event", item.EventType)
	req.Header.Set("X-Koschei-Timestamp", timestamp)
	req.Header.Set("X-Koschei-Signature", Signature(secret, timestamp, payload))
	if item.EventID.Valid {
		req.Header.Set("X-Koschei-Event-ID", item.EventID.String)
	}

	resp, err := client.Do(req)
	if err != nil {
		markDeliveryFailure(ctx, db, item, 0, sanitizeError(err), "", true)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	excerpt := sanitizeExcerpt(string(body))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		markDeliverySuccess(ctx, db, item, resp.StatusCode, excerpt)
		return
	}
	retryable := resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooEarly || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
	markDeliveryFailure(ctx, db, item, resp.StatusCode, fmt.Sprintf("endpoint returned HTTP %d", resp.StatusCode), excerpt, retryable)
}

func markDeliverySuccess(ctx context.Context, db *sql.DB, item deliveryRecord, status int, excerpt string) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
		UPDATE webhook_deliveries
		SET status='delivered',locked_at=NULL,last_http_status=$1,last_error=NULL,response_excerpt=$2,
		    delivered_at=now(),updated_at=now()
		WHERE id=$3`, status, excerpt, item.ID)
	if err != nil {
		return
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE webhook_endpoints
		SET failure_count=0,last_delivery_at=now(),last_success_at=now(),updated_at=now()
		WHERE id=$1`, item.EndpointID)
	if err == nil {
		_ = tx.Commit()
	}
}

func markDeliveryFailure(ctx context.Context, db *sql.DB, item deliveryRecord, httpStatus int, message, excerpt string, retryable bool) {
	status := "dead_letter"
	nextAttempt := time.Now().UTC()
	if retryable && item.AttemptCount < item.MaxAttempts {
		status = "retry"
		nextAttempt = nextRetryAt(time.Now().UTC(), item.AttemptCount)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	var nullableStatus any
	if httpStatus > 0 {
		nullableStatus = httpStatus
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE webhook_deliveries
		SET status=$1,locked_at=NULL,next_attempt_at=$2,last_http_status=$3,last_error=$4,
		    response_excerpt=$5,updated_at=now()
		WHERE id=$6`, status, nextAttempt, nullableStatus, truncate(message, 1000), excerpt, item.ID)
	if err != nil {
		return
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE webhook_endpoints
		SET failure_count=failure_count+1,last_delivery_at=now(),last_failure_at=now(),
		    status=CASE WHEN failure_count+1>=20 THEN 'paused' ELSE status END,updated_at=now()
		WHERE id=$1`, item.EndpointID)
	if err == nil {
		_ = tx.Commit()
	}
}

func nextRetryAt(now time.Time, attempt int) time.Time {
	delays := []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 8 * time.Hour, 24 * time.Hour}
	index := attempt - 1
	if index < 0 {
		index = 0
	}
	if index >= len(delays) {
		index = len(delays) - 1
	}
	return now.Add(delays[index])
}

func compactJSON(raw []byte) []byte {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return raw
	}
	compact, err := json.Marshal(value)
	if err != nil {
		return raw
	}
	return compact
}

func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	message = strings.ReplaceAll(message, "\n", " ")
	message = strings.ReplaceAll(message, "\r", " ")
	return truncate(message, 1000)
}

func sanitizeExcerpt(value string) string {
	value = strings.ReplaceAll(value, "\x00", "")
	value = strings.TrimSpace(value)
	return truncate(value, 2000)
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
