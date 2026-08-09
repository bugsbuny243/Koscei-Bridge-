package services

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"
)

const (
	pumpTradeLedgerQueueSize  = 4096
	pumpTradeLedgerBatchSize  = 100
	pumpTradeLedgerFlushEvery = 2 * time.Second
)

type TokenTradeEvent struct {
	Mint        string    `json:"mint"`
	Trader      string    `json:"trader"`
	Side        string    `json:"side"`
	SOLAmount   float64   `json:"sol_amount"`
	TokenAmount float64   `json:"token_amount"`
	Slot        int64     `json:"slot,omitempty"`
	BlockTime   time.Time `json:"block_time,omitempty"`
	Signature   string    `json:"signature"`
	Source      string    `json:"source"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
}

type PumpTradeLedgerWriter struct {
	db      *sql.DB
	queue   chan TokenTradeEvent
	dropped atomic.Uint64
}

func NewPumpTradeLedgerWriter(db *sql.DB) *PumpTradeLedgerWriter {
	return &PumpTradeLedgerWriter{db: db, queue: make(chan TokenTradeEvent, pumpTradeLedgerQueueSize)}
}

// PersistPumpPortal is the production PumpPortal trade commit path. The trade
// is written idempotently to token_trade_events before the websocket callback
// returns. This removes the bounded RAM queue and batch-discard windows from
// live trade capture while preserving the old queue API for compatibility.
func (w *PumpTradeLedgerWriter) PersistPumpPortal(ctx context.Context, event PumpPortalEvent) error {
	trade, ok := tokenTradeEventFromPumpPortal(event)
	if !ok {
		return nil
	}
	if w == nil || w.db == nil {
		return fmt.Errorf("pump trade ledger database unavailable")
	}
	backoffs := []time.Duration{0, 25 * time.Millisecond, 100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond, time.Second}
	var lastErr error
	for _, backoff := range backoffs {
		if backoff > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
		attemptCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := w.insertBatch(attemptCtx, []TokenTradeEvent{trade})
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("persist PumpPortal trade signature=%s: %w", trade.Signature, lastErr)
}

// EnqueuePumpPortal is retained for compatibility with older tests/callers.
// Production PumpPortal wiring uses PersistPumpPortal instead so queue pressure
// cannot silently drop a trade.
func (w *PumpTradeLedgerWriter) EnqueuePumpPortal(event PumpPortalEvent) bool {
	trade, ok := tokenTradeEventFromPumpPortal(event)
	if !ok || w == nil || w.db == nil {
		return false
	}
	select {
	case w.queue <- trade:
		return true
	default:
		dropped := w.dropped.Add(1)
		if dropped == 1 || dropped%100 == 0 {
			log.Printf("pump trade legacy queue full: not accepted=%d", dropped)
		}
		return false
	}
}

func (w *PumpTradeLedgerWriter) Start(ctx context.Context) {
	if w == nil || w.db == nil {
		return
	}
	ticker := time.NewTicker(pumpTradeLedgerFlushEvery)
	defer ticker.Stop()
	batch := make([]TokenTradeEvent, 0, pumpTradeLedgerBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		flushCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		if err := w.insertBatch(flushCtx, batch); err != nil {
			log.Printf("pump trade legacy batch insert failed rows=%d: %v", len(batch), err)
		}
		cancel()
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case event := <-w.queue:
					batch = append(batch, event)
					if len(batch) >= pumpTradeLedgerBatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case event := <-w.queue:
			batch = append(batch, event)
			if len(batch) >= pumpTradeLedgerBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (w *PumpTradeLedgerWriter) insertBatch(ctx context.Context, batch []TokenTradeEvent) error {
	if w == nil || w.db == nil || len(batch) == 0 {
		return nil
	}
	var query strings.Builder
	query.WriteString(`INSERT INTO token_trade_events
		(mint,trader,side,sol_amount,token_amount,slot,block_time,signature,source,created_at) VALUES `)
	args := make([]any, 0, len(batch)*10)
	rowCount := 0
	seen := map[string]bool{}
	for _, event := range batch {
		if event.Signature == "" || seen[event.Signature] {
			continue
		}
		seen[event.Signature] = true
		if rowCount > 0 {
			query.WriteByte(',')
		}
		base := rowCount*10 + 1
		query.WriteString(fmt.Sprintf("($%d,$%d,$%d,$%d,$%d,NULLIF($%d,0),$%d,$%d,$%d,$%d)", base, base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8, base+9))
		var blockTime any
		if !event.BlockTime.IsZero() {
			blockTime = event.BlockTime.UTC()
		}
		createdAt := event.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}
		args = append(args, event.Mint, event.Trader, event.Side, event.SOLAmount, event.TokenAmount, event.Slot, blockTime, event.Signature, event.Source, createdAt)
		rowCount++
	}
	if rowCount == 0 {
		return nil
	}
	query.WriteString(" ON CONFLICT (signature) DO NOTHING")
	_, err := w.db.ExecContext(ctx, query.String(), args...)
	return err
}

func tokenTradeEventFromPumpPortal(event PumpPortalEvent) (TokenTradeEvent, bool) {
	mint := strings.TrimSpace(event.Mint)
	trader := strings.TrimSpace(event.Trader)
	signature := strings.TrimSpace(event.Signature)
	side := normalizePumpPortalTradeSide(firstNonEmptyPumpPortal(event.Side, event.TxType))
	if mint == "" || trader == "" || signature == "" || (side != "buy" && side != "sell") {
		return TokenTradeEvent{}, false
	}
	blockTime := event.BlockTime
	if blockTime.IsZero() {
		blockTime = event.ReceivedAt
	}
	return TokenTradeEvent{
		Mint: mint, Trader: trader, Side: side,
		SOLAmount: event.SOLAmount, TokenAmount: event.TokenAmount,
		Slot: event.Slot, BlockTime: blockTime.UTC(), Signature: signature,
		Source: "pumpportal", CreatedAt: event.ReceivedAt.UTC(),
	}, true
}
