package services

import (
	"testing"
	"time"
)

func TestClassifyPumpPortalTradeStreamHealthNotConfigured(t *testing.T) {
	now := time.Date(2026, 8, 9, 16, 0, 0, 0, time.UTC)
	got := classifyPumpPortalTradeStreamHealth(PumpPortalTradeStreamHealth{Available: true, APIKeyConfigured: false}, now)
	if got != "not_configured" {
		t.Fatalf("expected not_configured, got %q", got)
	}
}

func TestClassifyPumpPortalTradeStreamHealthNoTradeObserved(t *testing.T) {
	now := time.Date(2026, 8, 9, 16, 0, 0, 0, time.UTC)
	got := classifyPumpPortalTradeStreamHealth(PumpPortalTradeStreamHealth{Available: true, APIKeyConfigured: true}, now)
	if got != "no_trade_observed" {
		t.Fatalf("expected no_trade_observed, got %q", got)
	}
}

func TestClassifyPumpPortalTradeStreamHealthObserved(t *testing.T) {
	now := time.Date(2026, 8, 9, 16, 0, 0, 0, time.UTC)
	last := now.Add(-2 * time.Minute)
	health := PumpPortalTradeStreamHealth{Available: true, APIKeyConfigured: true, TotalTrades: 10, Trades15m: 4, LastTradeAt: &last}
	if got := classifyPumpPortalTradeStreamHealth(health, now); got != "observed" {
		t.Fatalf("expected observed, got %q", got)
	}
}

func TestClassifyPumpPortalTradeStreamHealthStale(t *testing.T) {
	now := time.Date(2026, 8, 9, 16, 0, 0, 0, time.UTC)
	last := now.Add(-2 * time.Hour)
	health := PumpPortalTradeStreamHealth{Available: true, APIKeyConfigured: true, TotalTrades: 10, LastTradeAt: &last}
	if got := classifyPumpPortalTradeStreamHealth(health, now); got != "stale" {
		t.Fatalf("expected stale, got %q", got)
	}
}
