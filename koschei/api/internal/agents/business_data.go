package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type CatalogItem struct {
	ID           int64           `json:"id"`
	TenantID     string          `json:"tenant_id"`
	SKU          string          `json:"sku"`
	Kind         string          `json:"kind"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	PriceMinor   *int64          `json:"price_minor,omitempty"`
	Currency     string          `json:"currency"`
	Availability string          `json:"availability"`
	Metadata     json.RawMessage `json:"metadata"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

type KnowledgeEntry struct {
	ID        int64     `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Key       string    `json:"key"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	SourceURL string    `json:"source_url"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *Service) RegisterProviderEvent(ctx context.Context, tenantID string, channel Channel, providerMessageID string) (bool, error) {
	if s.db == nil {
		return true, nil
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO tradepi_agent_provider_events (tenant_id, channel, provider_message_id)
VALUES ($1,$2,$3)
ON CONFLICT (tenant_id, channel, provider_message_id) DO NOTHING`,
		strings.TrimSpace(tenantID), string(channel), strings.TrimSpace(providerMessageID))
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	return changed == 1, err
}

func (s *Service) ApplyBusinessContext(ctx context.Context, msg Message, result Result) Result {
	if s.db == nil {
		return result
	}
	if item, ok := s.matchCatalog(ctx, msg.TenantID, msg.Text); ok {
		availability := "Stok durumu henüz doğrulanmadı."
		switch item.Availability {
		case "available":
			availability = "İşletme kataloğunda mevcut görünüyor."
		case "unavailable":
			availability = "İşletme kataloğunda şu anda mevcut görünmüyor."
		}
		price := "Fiyat henüz doğrulanmadı."
		if item.PriceMinor != nil {
			price = fmt.Sprintf("Doğrulanmış katalog fiyatı: %.2f %s.", float64(*item.PriceMinor)/100, item.Currency)
		}
		description := strings.TrimSpace(item.Description)
		if len(description) > 320 {
			description = description[:320] + "…"
		}
		result.Reply = strings.TrimSpace(fmt.Sprintf("%s — %s %s %s", item.Name, description, price, availability))
		return result
	}
	if entry, ok := s.matchKnowledge(ctx, msg.TenantID, msg.Text); ok {
		body := strings.TrimSpace(entry.Body)
		if len(body) > 700 {
			body = body[:700] + "…"
		}
		result.Reply = body
	}
	return result
}

func (s *Service) matchCatalog(ctx context.Context, tenantID, query string) (CatalogItem, bool) {
	var item CatalogItem
	q := "%" + strings.TrimSpace(query) + "%"
	if q == "%%" {
		return item, false
	}
	err := s.db.QueryRowContext(ctx, `
SELECT id, tenant_id, sku, kind, name, description, price_minor, currency, availability, metadata, updated_at
FROM tradepi_agent_catalog_items
WHERE tenant_id=$1 AND ($2 ILIKE '%' || sku || '%' OR $2 ILIKE '%' || name || '%' OR name ILIKE $3 OR description ILIKE $3)
ORDER BY CASE WHEN $2 ILIKE '%' || sku || '%' THEN 0 WHEN $2 ILIKE '%' || name || '%' THEN 1 ELSE 2 END, updated_at DESC
LIMIT 1`, strings.TrimSpace(tenantID), strings.TrimSpace(query), q).Scan(
		&item.ID, &item.TenantID, &item.SKU, &item.Kind, &item.Name, &item.Description, &item.PriceMinor, &item.Currency, &item.Availability, &item.Metadata, &item.UpdatedAt,
	)
	return item, err == nil
}

func (s *Service) matchKnowledge(ctx context.Context, tenantID, query string) (KnowledgeEntry, bool) {
	var item KnowledgeEntry
	q := "%" + strings.TrimSpace(query) + "%"
	if q == "%%" {
		return item, false
	}
	err := s.db.QueryRowContext(ctx, `
SELECT id, tenant_id, key, title, body, source_url, updated_at
FROM tradepi_agent_knowledge_entries
WHERE tenant_id=$1 AND ($2 ILIKE '%' || key || '%' OR $2 ILIKE '%' || title || '%' OR title ILIKE $3)
ORDER BY updated_at DESC
LIMIT 1`, strings.TrimSpace(tenantID), strings.TrimSpace(query), q).Scan(
		&item.ID, &item.TenantID, &item.Key, &item.Title, &item.Body, &item.SourceURL, &item.UpdatedAt,
	)
	return item, err == nil
}

func (s *Service) AdminCatalog(ctx context.Context, tenantID string, limit int) ([]CatalogItem, error) {
	if s.db == nil {
		return nil, ErrPersistenceUnavailable
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, tenant_id, sku, kind, name, description, price_minor, currency, availability, metadata, updated_at
FROM tradepi_agent_catalog_items
WHERE tenant_id=$1
ORDER BY updated_at DESC, id DESC
LIMIT $2`, strings.TrimSpace(tenantID), adminLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]CatalogItem, 0)
	for rows.Next() {
		var item CatalogItem
		if err := rows.Scan(&item.ID, &item.TenantID, &item.SKU, &item.Kind, &item.Name, &item.Description, &item.PriceMinor, &item.Currency, &item.Availability, &item.Metadata, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Service) AdminUpsertCatalog(ctx context.Context, item CatalogItem) error {
	if s.db == nil {
		return ErrPersistenceUnavailable
	}
	item.TenantID = strings.TrimSpace(item.TenantID)
	item.SKU = strings.TrimSpace(item.SKU)
	item.Kind = firstValue(item.Kind, "product")
	item.Name = strings.TrimSpace(item.Name)
	item.Currency = strings.ToUpper(firstValue(item.Currency, "TRY"))
	item.Availability = strings.ToLower(firstValue(item.Availability, "unknown"))
	if item.TenantID == "" || item.SKU == "" || item.Name == "" {
		return ErrInvalidAdminTransition
	}
	if item.Availability != "unknown" && item.Availability != "available" && item.Availability != "unavailable" {
		return ErrInvalidAdminTransition
	}
	metadata := item.Metadata
	if len(metadata) == 0 || !json.Valid(metadata) {
		metadata = json.RawMessage(`{}`)
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO tradepi_agent_catalog_items (tenant_id, sku, kind, name, description, price_minor, currency, availability, metadata, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
ON CONFLICT (tenant_id, sku) DO UPDATE SET
 kind=EXCLUDED.kind, name=EXCLUDED.name, description=EXCLUDED.description,
 price_minor=EXCLUDED.price_minor, currency=EXCLUDED.currency,
 availability=EXCLUDED.availability, metadata=EXCLUDED.metadata, updated_at=NOW()`,
		item.TenantID, item.SKU, item.Kind, item.Name, item.Description, item.PriceMinor, item.Currency, item.Availability, metadata)
	return err
}

func (s *Service) AdminKnowledge(ctx context.Context, tenantID string, limit int) ([]KnowledgeEntry, error) {
	if s.db == nil {
		return nil, ErrPersistenceUnavailable
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, tenant_id, key, title, body, source_url, updated_at
FROM tradepi_agent_knowledge_entries
WHERE tenant_id=$1
ORDER BY updated_at DESC, id DESC
LIMIT $2`, strings.TrimSpace(tenantID), adminLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]KnowledgeEntry, 0)
	for rows.Next() {
		var item KnowledgeEntry
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Key, &item.Title, &item.Body, &item.SourceURL, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Service) AdminUpsertKnowledge(ctx context.Context, item KnowledgeEntry) error {
	if s.db == nil {
		return ErrPersistenceUnavailable
	}
	item.TenantID = strings.TrimSpace(item.TenantID)
	item.Key = strings.TrimSpace(item.Key)
	item.Title = strings.TrimSpace(item.Title)
	item.Body = strings.TrimSpace(item.Body)
	if item.TenantID == "" || item.Key == "" || item.Title == "" || item.Body == "" {
		return ErrInvalidAdminTransition
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO tradepi_agent_knowledge_entries (tenant_id, key, title, body, source_url, updated_at)
VALUES ($1,$2,$3,$4,$5,NOW())
ON CONFLICT (tenant_id, key) DO UPDATE SET
 title=EXCLUDED.title, body=EXCLUDED.body, source_url=EXCLUDED.source_url, updated_at=NOW()`,
		item.TenantID, item.Key, item.Title, item.Body, strings.TrimSpace(item.SourceURL))
	return err
}

func firstValue(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}
