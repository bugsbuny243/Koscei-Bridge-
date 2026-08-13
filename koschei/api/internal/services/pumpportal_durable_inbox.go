package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

const (
	pumpPortalInboxBatchSize       = 50
	pumpPortalInboxRecoveryCeiling = 30 * time.Second
	pumpPortalInboxMaxAttempts     = 5
)

type PumpPortalDurableInbox struct {
	DB      *sql.DB
	Adapter *PumpPortalRadarAdapter
	wake    chan struct{}
}

type pumpPortalInboxItem struct {
	ID       string
	Payload  []byte
	Attempts int
}

func NewPumpPortalDurableInbox(db *sql.DB, adapter *PumpPortalRadarAdapter) *PumpPortalDurableInbox {
	return &PumpPortalDurableInbox{DB: db, Adapter: adapter, wake: make(chan struct{}, 1)}
}

// PersistDiscovery is the PumpPortal websocket commit point. Discovery events
// are not acknowledged to the caller until they are durable in Postgres (or an
// identical event_key is already present). Bounded retries absorb short Neon
// wake-up/network hiccups without falling back to a lossy RAM queue.
func (q *PumpPortalDurableInbox) PersistDiscovery(ctx context.Context, event PumpPortalEvent) error {
	if q == nil || q.DB == nil {
		return errors.New("pumpportal durable inbox unavailable")
	}
	if isPumpPortalTradeEvent(event) {
		return nil
	}
	mint := resolvePumpPortalMint(event)
	if mint == "" {
		return nil
	}
	eventType := pumpPortalEventType(event)
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode pumpportal inbox event: %w", err)
	}
	key := pumpPortalInboxEventKey(event)
	if key == "" {
		return errors.New("pumpportal inbox event key unavailable")
	}
	receivedAt := event.ReceivedAt.UTC()
	if receivedAt.IsZero() {
		receivedAt = time.Now().UTC()
	}

	var lastErr error
	backoffs := []time.Duration{0, 25 * time.Millisecond, 100 * time.Millisecond, 250 * time.Millisecond}
	for _, backoff := range backoffs {
		if backoff > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
		var id string
		err = q.DB.QueryRowContext(ctx, `
			INSERT INTO pumpportal_event_inbox
			(event_key,network,signature,mint,event_type,payload,status,attempts,last_error,received_at,created_at,updated_at)
			VALUES($1,'solana-mainnet',$2,$3,$4,$5::jsonb,'pending',0,'',$6,now(),now())
			ON CONFLICT(event_key) DO NOTHING
			RETURNING id::text
		`, key, strings.TrimSpace(event.Signature), mint, eventType, string(payload), receivedAt).Scan(&id)
		if err == nil || errors.Is(err, sql.ErrNoRows) {
			q.signal()
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("persist pumpportal discovery event: %w", lastErr)
}

func (q *PumpPortalDurableInbox) Start(ctx context.Context) {
	if q == nil || q.DB == nil || q.Adapter == nil {
		return
	}
	log.Printf("pumpportal durable inbox worker started mode=event-driven recovery-ceiling=%s batch=%d", pumpPortalInboxRecoveryCeiling, pumpPortalInboxBatchSize)
	q.processAvailable(ctx)
	ticker := time.NewTicker(pumpPortalInboxRecoveryCeiling)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-q.wake:
			q.processAvailable(ctx)
		case <-ticker.C:
			q.processAvailable(ctx)
		}
	}
}

func (q *PumpPortalDurableInbox) signal() {
	if q == nil || q.wake == nil {
		return
	}
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *PumpPortalDurableInbox) processAvailable(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		items, err := q.claimBatch(ctx, pumpPortalInboxBatchSize)
		if err != nil {
			if !isUndefinedTableError(err) && ctx.Err() == nil {
				log.Printf("pumpportal durable inbox claim failed: %v", err)
			}
			return
		}
		if len(items) == 0 {
			return
		}
		for _, item := range items {
			q.processOne(ctx, item)
		}
	}
}

func (q *PumpPortalDurableInbox) claimBatch(ctx context.Context, limit int) ([]pumpPortalInboxItem, error) {
	if limit <= 0 || limit > 200 {
		limit = pumpPortalInboxBatchSize
	}
	rows, err := q.DB.QueryContext(ctx, `
		WITH candidates AS (
			SELECT id
			FROM pumpportal_event_inbox
			WHERE
				status='pending'
				OR (status='retryable' AND attempts < $2 AND updated_at < now() - interval '2 seconds')
				OR (status='processing' AND updated_at < now() - interval '2 minutes')
			ORDER BY received_at ASC,created_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $1
		)
		UPDATE pumpportal_event_inbox i
		SET status='processing',attempts=i.attempts+1,last_error='',updated_at=now()
		FROM candidates c
		WHERE i.id=c.id
		RETURNING i.id::text,i.payload,i.attempts
	`, limit, pumpPortalInboxMaxAttempts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []pumpPortalInboxItem{}
	for rows.Next() {
		var item pumpPortalInboxItem
		if err := rows.Scan(&item.ID, &item.Payload, &item.Attempts); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (q *PumpPortalDurableInbox) processOne(ctx context.Context, item pumpPortalInboxItem) {
	var event PumpPortalEvent
	if err := json.Unmarshal(item.Payload, &event); err != nil {
		q.finish(ctx, item, fmt.Errorf("decode durable pumpportal event: %w", err))
		return
	}
	err := q.Adapter.HandleEvent(ctx, event)
	q.finish(ctx, item, err)
}

func (q *PumpPortalDurableInbox) finish(ctx context.Context, item pumpPortalInboxItem, processErr error) {
	if q == nil || q.DB == nil {
		return
	}
	if processErr == nil {
		_, err := q.DB.ExecContext(ctx, `
			UPDATE pumpportal_event_inbox
			SET status='completed',last_error='',processed_at=now(),updated_at=now()
			WHERE id=$1::uuid
		`, item.ID)
		if err != nil && ctx.Err() == nil {
			log.Printf("pumpportal durable inbox completion update failed id=%s: %v", item.ID, err)
		}
		return
	}
	status := "retryable"
	if item.Attempts >= pumpPortalInboxMaxAttempts {
		status = "exhausted"
	}
	message := strings.TrimSpace(processErr.Error())
	if len(message) > 500 {
		message = message[:500]
	}
	_, err := q.DB.ExecContext(ctx, `
		UPDATE pumpportal_event_inbox
		SET status=$2,last_error=$3,updated_at=now()
		WHERE id=$1::uuid
	`, item.ID, status, message)
	if err != nil && ctx.Err() == nil {
		log.Printf("pumpportal durable inbox failure update failed id=%s: %v", item.ID, err)
	}
}

func pumpPortalInboxEventKey(event PumpPortalEvent) string {
	if signature := strings.TrimSpace(event.Signature); signature != "" {
		return "sig:" + signature
	}
	identity := struct {
		Mint      string `json:"mint"`
		Type      string `json:"type"`
		Creator   string `json:"creator"`
		Trader    string `json:"trader"`
		TxType    string `json:"tx_type"`
		Slot      int64  `json:"slot"`
		BlockTime string `json:"block_time"`
	}{
		Mint:    strings.TrimSpace(resolvePumpPortalMint(event)),
		Type:    strings.TrimSpace(pumpPortalEventType(event)),
		Creator: strings.TrimSpace(event.Creator),
		Trader:  strings.TrimSpace(event.Trader),
		TxType:  strings.TrimSpace(event.TxType),
		Slot:    event.Slot,
	}
	if !event.BlockTime.IsZero() {
		identity.BlockTime = event.BlockTime.UTC().Format(time.RFC3339Nano)
	}
	if identity.Mint == "" {
		return ""
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}
