package http

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/agents"
)

type agentCatalogUpsertRequest struct {
	TenantID     string          `json:"tenant_id"`
	SKU          string          `json:"sku"`
	Kind         string          `json:"kind"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	PriceMinor   *int64          `json:"price_minor"`
	Currency     string          `json:"currency"`
	Availability string          `json:"availability"`
	Metadata     json.RawMessage `json:"metadata"`
}

type agentKnowledgeUpsertRequest struct {
	TenantID  string `json:"tenant_id"`
	Key       string `json:"key"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	SourceURL string `json:"source_url"`
}

func registerTradePIAgentExtendedRoutes(mux *http.ServeMux) {
	tradePIAgentService.StartFollowupWorker()
	mux.HandleFunc("/webhooks/whatsapp", tradePIWhatsAppWebhook)
	mux.HandleFunc("/api/agents/admin/catalog", tradePIAgentAdminCatalog)
	mux.HandleFunc("/api/agents/admin/catalog/upsert", tradePIAgentAdminCatalogUpsert)
	mux.HandleFunc("/api/agents/admin/knowledge", tradePIAgentAdminKnowledge)
	mux.HandleFunc("/api/agents/admin/knowledge/upsert", tradePIAgentAdminKnowledgeUpsert)
}

func tradePIWhatsAppWebhook(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tradePIWhatsAppVerify(w, r)
	case http.MethodPost:
		tradePIWhatsAppReceive(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func tradePIWhatsAppVerify(w http.ResponseWriter, r *http.Request) {
	expected := strings.TrimSpace(os.Getenv("WHATSAPP_VERIFY_TOKEN"))
	provided := strings.TrimSpace(r.URL.Query().Get("hub.verify_token"))
	if expected == "" || r.URL.Query().Get("hub.mode") != "subscribe" || !constantTimeAgentEqual(provided, expected) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(r.URL.Query().Get("hub.challenge")))
}

func tradePIWhatsAppReceive(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if secret := strings.TrimSpace(os.Getenv("WHATSAPP_APP_SECRET")); secret != "" && !validWhatsAppSignature(body, r.Header.Get("X-Hub-Signature-256"), secret) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	var payload struct {
		Entry []struct {
			Changes []struct {
				Value struct {
					Metadata struct {
						PhoneNumberID string `json:"phone_number_id"`
					} `json:"metadata"`
					Contacts []struct {
						WAID    string `json:"wa_id"`
						Profile struct {
							Name string `json:"name"`
						} `json:"profile"`
					} `json:"contacts"`
					Messages []struct {
						ID        string `json:"id"`
						From      string `json:"from"`
						Timestamp string `json:"timestamp"`
						Type      string `json:"type"`
						Text      struct {
							Body string `json:"body"`
						} `json:"text"`
					} `json:"messages"`
				} `json:"value"`
			} `json:"changes"`
		} `json:"entry"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	processed, sent, unrouted := 0, 0, 0
	for _, entry := range payload.Entry {
		for _, change := range entry.Changes {
			if len(change.Value.Messages) == 0 {
				continue
			}
			phoneID := strings.TrimSpace(change.Value.Metadata.PhoneNumberID)
			account, accountErr := tradePIAgentService.ResolveChannelAccount(r.Context(), agents.ChannelWhatsApp, "", phoneID)
			if accountErr != nil {
				unrouted += len(change.Value.Messages)
				continue
			}
			nameByWAID := map[string]string{}
			for _, c := range change.Value.Contacts {
				nameByWAID[c.WAID] = strings.TrimSpace(c.Profile.Name)
			}
			for _, incoming := range change.Value.Messages {
				if incoming.Type != "text" || strings.TrimSpace(incoming.Text.Body) == "" || strings.TrimSpace(incoming.From) == "" {
					continue
				}
				fresh, err := tradePIAgentService.RegisterProviderEvent(r.Context(), account.TenantID, agents.ChannelWhatsApp, incoming.ID)
				if err != nil || !fresh {
					continue
				}
				receivedAt := time.Now().UTC()
				if unixValue, err := parseUnixSeconds(incoming.Timestamp); err == nil {
					receivedAt = unixValue
				}
				msg := agents.Message{
					TenantID:         account.TenantID,
					Channel:          agents.ChannelWhatsApp,
					ChannelAccountID: account.ID,
					ChannelChatID:    incoming.From,
					ChannelUserID:    incoming.From,
					DisplayName:      nameByWAID[incoming.From],
					Text:             incoming.Text.Body,
					ReceivedAt:       receivedAt,
				}
				result := tradePIAgentService.Handle(r.Context(), msg)
				processed++
				if agents.WhatsAppAccountOutboundEnabled(account.ProviderAccountID) {
					if err := agents.SendWhatsAppTextFrom(r.Context(), account.ProviderAccountID, incoming.From, result.Reply); err == nil {
						sent++
						tradePIAgentService.RecordOutbound(r.Context(), msg, result.Reply)
					}
				}
			}
		}
	}
	writeTradePIAgentJSON(w, map[string]any{"ok": true, "processed": processed, "sent": sent, "unrouted": unrouted})
}

func validWhatsAppSignature(body []byte, signature, secret string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hmac.Equal(provided, mac.Sum(nil))
}

func constantTimeAgentEqual(a, b string) bool {
	aHash := sha256.Sum256([]byte(a))
	bHash := sha256.Sum256([]byte(b))
	return hmac.Equal(aHash[:], bHash[:])
}

func parseUnixSeconds(value string) (time.Time, error) {
	seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(seconds, 0).UTC(), nil
}

func tradePIAgentAdminCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	items, err := tradePIAgentService.AdminCatalog(r.Context(), tradePIAgentAdminTenant(r), tradePIAgentAdminLimit(r))
	if err != nil {
		http.Error(w, "catalog unavailable", http.StatusServiceUnavailable)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"items": items})
}

func tradePIAgentAdminCatalogUpsert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	var req agentCatalogUpsertRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	item := agents.CatalogItem{
		TenantID: firstNonEmpty(req.TenantID, os.Getenv("TRADEPI_DEFAULT_TENANT"), "demo-automotive"),
		SKU: req.SKU, Kind: req.Kind, Name: req.Name, Description: req.Description,
		PriceMinor: req.PriceMinor, Currency: req.Currency, Availability: req.Availability, Metadata: req.Metadata,
	}
	if err := tradePIAgentService.AdminUpsertCatalog(r.Context(), item); err != nil {
		http.Error(w, "catalog update rejected", http.StatusConflict)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"ok": true, "sku": req.SKU})
}

func tradePIAgentAdminKnowledge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	items, err := tradePIAgentService.AdminKnowledge(r.Context(), tradePIAgentAdminTenant(r), tradePIAgentAdminLimit(r))
	if err != nil {
		http.Error(w, "knowledge unavailable", http.StatusServiceUnavailable)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"items": items})
}

func tradePIAgentAdminKnowledgeUpsert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !tradePIAgentAdminAuthorized(w, r) {
		return
	}
	var req agentKnowledgeUpsertRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	item := agents.KnowledgeEntry{
		TenantID: firstNonEmpty(req.TenantID, os.Getenv("TRADEPI_DEFAULT_TENANT"), "demo-automotive"),
		Key: req.Key, Title: req.Title, Body: req.Body, SourceURL: req.SourceURL,
	}
	if err := tradePIAgentService.AdminUpsertKnowledge(r.Context(), item); err != nil {
		http.Error(w, "knowledge update rejected", http.StatusConflict)
		return
	}
	writeTradePIAgentJSON(w, map[string]any{"ok": true, "key": req.Key})
}
