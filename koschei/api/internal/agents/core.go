package agents

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type Channel string

const (
	ChannelTelegram Channel = "telegram"
	ChannelWhatsApp Channel = "whatsapp"
	ChannelWeb      Channel = "web"
)

type Message struct {
	TenantID      string
	Channel       Channel
	ChannelChatID string
	ChannelUserID string
	DisplayName   string
	Text          string
	ReceivedAt    time.Time
}

type Lead struct {
	TenantID      string    `json:"tenant_id"`
	ExternalID    string    `json:"external_id"`
	DisplayName   string    `json:"display_name"`
	Stage         string    `json:"stage"`
	Score         int       `json:"score"`
	BudgetKnown   bool      `json:"budget_known"`
	ModelKnown    bool      `json:"model_known"`
	LocationKnown bool      `json:"location_known"`
	TradeInKnown  bool      `json:"trade_in_known"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Vehicle struct {
	ID       string `json:"id"`
	Make     string `json:"make"`
	Model    string `json:"model"`
	Year     int    `json:"year"`
	PriceTRY int64  `json:"price_try"`
	City     string `json:"city"`
	InStock  bool   `json:"in_stock"`
}

type Result struct {
	Lead     Lead      `json:"lead"`
	Reply    string    `json:"reply"`
	Vehicles []Vehicle `json:"vehicles,omitempty"`
}

type Inventory interface {
	Search(ctx context.Context, query string) ([]Vehicle, error)
}

type Core struct{ inventory Inventory }

func NewCore(inventory Inventory) *Core { return &Core{inventory: inventory} }

func (c *Core) Handle(ctx context.Context, msg Message, current Lead) Result {
	lead := qualify(msg, current)
	var vehicles []Vehicle
	if c.inventory != nil && lead.ModelKnown {
		vehicles, _ = c.inventory.Search(ctx, modelQuery(msg.Text))
	}
	return Result{Lead: lead, Reply: buildReply(lead, vehicles), Vehicles: vehicles}
}

func qualify(msg Message, lead Lead) Lead {
	text := strings.ToLower(msg.Text)
	if lead.TenantID == "" {
		lead.TenantID = msg.TenantID
		lead.ExternalID = msg.ChannelUserID
		lead.DisplayName = msg.DisplayName
		lead.Stage = "new"
	}
	if strings.TrimSpace(msg.Text) != "" && lead.Stage == "new" {
		lead.Stage = "engaged"
	}
	if containsAny(text, "bmw", "mercedes", "audi", "tesla", "toyota", "ford", "renault", "fiat", "320i", "520i", "c200") {
		lead.ModelKnown = true
	}
	if containsAny(text, "bütçe", "butce", "tl", "₺", "eur", "€", "usd", "$", "milyon", "bin") {
		lead.BudgetKnown = true
	}
	if containsAny(text, "istanbul", "ankara", "izmir", "bursa", "antalya", "konya", "adana", "şehir", "sehir") {
		lead.LocationKnown = true
	}
	if containsAny(text, "takas", "trade-in", "aracımı", "arabamı", "aracimi", "arabami") {
		lead.TradeInKnown = true
	}

	score := 10
	if lead.ModelKnown { score += 25 }
	if lead.BudgetKnown { score += 25 }
	if lead.LocationKnown { score += 20 }
	if lead.TradeInKnown { score += 10 }
	if containsAny(text, "test sürüş", "test surus", "randevu", "bugün", "bugun", "yarın", "yarin") { score += 20 }
	if score > 100 { score = 100 }
	lead.Score = score
	if score >= 60 && lead.Stage == "engaged" { lead.Stage = "qualified" }
	lead.UpdatedAt = time.Now().UTC()
	return lead
}

func buildReply(lead Lead, vehicles []Vehicle) string {
	if len(vehicles) > 0 {
		v := vehicles[0]
		return fmt.Sprintf("Doğrulanmış demo stoğunda %s %s (%d) görünüyor. Fiyat: %d TL, şehir: %s. İstersen test sürüşü veya satış temsilcisine aktarım başlatabiliriz.", v.Make, v.Model, v.Year, v.PriceTRY, v.City)
	}
	if lead.Stage == "qualified" {
		return "İhtiyacın netleşti. Gerçek stok entegrasyonu bağlandığında yalnızca doğrulanmış araç seçenekleri sunacağım."
	}
	return "İlgilendiğin model, yaklaşık bütçe ve bulunduğun şehri yazabilirsin."
}

func modelQuery(text string) string {
	lower := strings.ToLower(text)
	for _, model := range []string{"320i", "520i", "c200"} {
		if strings.Contains(lower, model) { return model }
	}
	return text
}

func containsAny(s string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(s, value) { return true }
	}
	return false
}
