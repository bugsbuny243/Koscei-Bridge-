package agents

import (
	"context"
	"strings"
	"sync"
)

type DemoInventory struct {
	vehicles []Vehicle
}

func NewDemoInventory() *DemoInventory {
	return &DemoInventory{vehicles: []Vehicle{
		{ID: "demo-bmw-320i", Make: "BMW", Model: "320i", Year: 2025, PriceTRY: 2450000, City: "Istanbul", InStock: true},
		{ID: "demo-bmw-520i", Make: "BMW", Model: "520i", Year: 2024, PriceTRY: 3650000, City: "Istanbul", InStock: true},
		{ID: "demo-mercedes-c200", Make: "Mercedes-Benz", Model: "C200", Year: 2025, PriceTRY: 3350000, City: "Ankara", InStock: true},
	}}
}

func (d *DemoInventory) Search(_ context.Context, query string) ([]Vehicle, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	out := make([]Vehicle, 0)
	for _, vehicle := range d.vehicles {
		haystack := strings.ToLower(vehicle.Make + " " + vehicle.Model + " " + vehicle.City)
		if vehicle.InStock && (q == "" || strings.Contains(haystack, q) || strings.Contains(q, strings.ToLower(vehicle.Model))) {
			out = append(out, vehicle)
		}
	}
	return out, nil
}

type Service struct {
	mu    sync.RWMutex
	leads map[string]Lead
	core  *Core
}

func NewService() *Service {
	return &Service{leads: map[string]Lead{}, core: NewCore(NewDemoInventory())}
}

func (s *Service) Handle(ctx context.Context, msg Message) Result {
	key := msg.TenantID + ":" + string(msg.Channel) + ":" + msg.ChannelUserID
	s.mu.RLock()
	current := s.leads[key]
	s.mu.RUnlock()

	result := s.core.Handle(ctx, msg, current)

	s.mu.Lock()
	s.leads[key] = result.Lead
	s.mu.Unlock()
	return result
}
