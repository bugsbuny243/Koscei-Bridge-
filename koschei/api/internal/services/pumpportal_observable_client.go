package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

type PumpPortalTradeRuntimeSnapshot struct {
	Status        string    `json:"status"`
	UpdatedAt     time.Time `json:"updated_at"`
	NoticeClass   string    `json:"notice_class,omitempty"`
	TrackedMints  int       `json:"tracked_mints"`
	TradeObserved bool      `json:"trade_observed"`
}

var pumpPortalTradeRuntime = struct {
	sync.RWMutex
	value PumpPortalTradeRuntimeSnapshot
}{value: PumpPortalTradeRuntimeSnapshot{Status: "not_started"}}

func setPumpPortalTradeRuntime(status, notice string, tracked int, observed bool) {
	pumpPortalTradeRuntime.Lock()
	pumpPortalTradeRuntime.value = PumpPortalTradeRuntimeSnapshot{
		Status:        strings.TrimSpace(status),
		UpdatedAt:     time.Now().UTC(),
		NoticeClass:   strings.TrimSpace(notice),
		TrackedMints:  tracked,
		TradeObserved: observed,
	}
	pumpPortalTradeRuntime.Unlock()
}

func CurrentPumpPortalTradeRuntime() PumpPortalTradeRuntimeSnapshot {
	pumpPortalTradeRuntime.RLock()
	defer pumpPortalTradeRuntime.RUnlock()
	return pumpPortalTradeRuntime.value
}

type PumpPortalObservableClient struct {
	base *PumpPortalClient
}

func NewPumpPortalObservableClient(cfg PumpPortalConfig) *PumpPortalObservableClient {
	base := NewPumpPortalClient(cfg)
	status := "configured"
	if strings.TrimSpace(cfg.APIKey) == "" {
		status = "trade_auth_not_configured"
	}
	setPumpPortalTradeRuntime(status, "", 0, false)
	return &PumpPortalObservableClient{base: base}
}

func (c *PumpPortalObservableClient) Start(ctx context.Context, onEvent func(context.Context, PumpPortalEvent) error) {
	if c == nil || c.base == nil || !c.base.Config.Enabled || onEvent == nil {
		return
	}
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := c.run(ctx, onEvent); err != nil && ctx.Err() == nil {
			log.Printf("pumpportal observable websocket disconnected: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
			if backoff > time.Minute {
				backoff = time.Minute
			}
		}
	}
}

func (c *PumpPortalObservableClient) run(ctx context.Context, onEvent func(context.Context, PumpPortalEvent) error) error {
	conn, err := dialPumpPortalWebSocket(ctx, c.base.Config.websocketURL())
	if err != nil {
		return err
	}
	defer conn.Close()
	tradeAuth := strings.TrimSpace(c.base.Config.APIKey) != ""
	log.Printf("pumpportal data websocket connected: %s trade_auth_configured=%t", c.base.Config.redactedWebsocketHost(), tradeAuth)
	for _, msg := range []map[string]any{{"method": "subscribeNewToken"}, {"method": "subscribeMigration"}} {
		if err := writeWebSocketText(conn, msg); err != nil {
			return err
		}
	}
	if tradeAuth {
		for _, keys := range c.base.tradeSubscriptionBatches() {
			if err := writeWebSocketText(conn, map[string]any{"method": "subscribeTokenTrade", "keys": keys}); err != nil {
				return err
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			_ = writeWebSocketClose(conn)
			return nil
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(75 * time.Second))
		payload, opcode, err := readWebSocketFrame(conn)
		if err != nil {
			return err
		}
		switch opcode {
		case 1:
			if noticeClass, handled := classifyPumpPortalProviderNotice(payload); handled {
				current := CurrentPumpPortalTradeRuntime()
				status := current.Status
				switch noticeClass {
				case "trade_subscription_rejected":
					status = "subscription_rejected"
					setPumpPortalTradeRuntime(status, noticeClass, len(c.base.tradeOrder), current.TradeObserved)
					log.Printf("pumpportal provider notice class=%s", noticeClass)
				case "subscription_acknowledged":
					if status != "trade_observed" && status != "subscription_rejected" {
						status = "subscription_acknowledged"
					}
					setPumpPortalTradeRuntime(status, noticeClass, len(c.base.tradeOrder), current.TradeObserved)
				default:
					setPumpPortalTradeRuntime(status, noticeClass, len(c.base.tradeOrder), current.TradeObserved)
				}
				continue
			}
			event, ok := parsePumpPortalEvent(payload)
			if !ok {
				continue
			}
			if isPumpPortalTradeEvent(event) {
				setPumpPortalTradeRuntime("trade_observed", "", len(c.base.tradeOrder), true)
			}
			if c.base.shouldTrackMint(event) {
				added, evicted := c.base.rememberTradeMint(event.Mint)
				if evicted != "" && tradeAuth {
					if err := writeWebSocketText(conn, map[string]any{"method": "unsubscribeTokenTrade", "keys": []string{evicted}}); err != nil {
						return err
					}
				}
				if added && tradeAuth {
					if err := writeWebSocketText(conn, map[string]any{"method": "subscribeTokenTrade", "keys": []string{event.Mint}}); err != nil {
						return err
					}
					setPumpPortalTradeRuntime("subscription_requested", "", len(c.base.tradeOrder), CurrentPumpPortalTradeRuntime().TradeObserved)
				}
			}
			if err := onEvent(ctx, event); err != nil {
				return fmt.Errorf("pumpportal durable event adapter: %w", err)
			}
		case 8:
			return fmt.Errorf("websocket closed by server")
		case 9:
			_ = writeWebSocketControl(conn, 10, payload)
		}
	}
}

// classifyPumpPortalProviderNotice classifies non-event JSON without returning
// or logging the raw payload. Provider responses can contain operational detail;
// the control plane exposes only bounded classes.
func classifyPumpPortalProviderNotice(payload []byte) (string, bool) {
	var raw map[string]any
	if json.Unmarshal(payload, &raw) != nil || raw == nil {
		return "", false
	}
	for _, key := range []string{"mint", "tokenMint", "ca", "address"} {
		if value, ok := raw[key].(string); ok && strings.TrimSpace(value) != "" {
			return "", false
		}
	}
	parts := []string{}
	for _, key := range []string{"message", "error", "status", "detail", "reason"} {
		if value, ok := raw[key].(string); ok && strings.TrimSpace(value) != "" {
			parts = append(parts, strings.ToLower(strings.TrimSpace(value)))
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	text := strings.Join(parts, " ")
	tradeRelated := strings.Contains(text, "trade") || strings.Contains(text, "subscription") || strings.Contains(text, "subscribe")
	authRelated := strings.Contains(text, "api key") || strings.Contains(text, "api-key") || strings.Contains(text, "wallet") || strings.Contains(text, "balance") || strings.Contains(text, "fund") || strings.Contains(text, "payment") || strings.Contains(text, "unauthor") || strings.Contains(text, "forbidden")
	failure := strings.Contains(text, "error") || strings.Contains(text, "fail") || strings.Contains(text, "reject") || strings.Contains(text, "require") || strings.Contains(text, "insufficient") || strings.Contains(text, "invalid") || strings.Contains(text, "unauthor") || strings.Contains(text, "forbidden")
	if (tradeRelated || authRelated) && failure {
		return "trade_subscription_rejected", true
	}

	// Only explicit acknowledgement language may advance runtime state. A generic
	// provider sentence such as "subscription successful" is informational and
	// does not prove which requested subscription was actually acknowledged.
	ack := strings.Contains(text, "subscribed") || strings.Contains(text, "acknowledged") || strings.Contains(text, "acknowledgement")
	if ack {
		return "subscription_acknowledged", true
	}
	return "provider_notice", true
}
