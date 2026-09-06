package handlers

import (
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestBuildCreatorTokenRecurrenceRequiresTwoDistinctMints(t *testing.T) {
	observed := newCreatorTokenObservedPathsReport("Creator111")
	observed.Paths = []creatorTokenObservedPath{
		{Mint: "MintA", Counterparty: "Dex111", CounterpartyKind: services.WalletEntityKindDEX, Signature: "sig-a1", Slot: 101, ObservedAt: time.Now().UTC()},
		{Mint: "MintA", Counterparty: "Dex111", CounterpartyKind: services.WalletEntityKindDEX, Signature: "sig-a2", Slot: 102, ObservedAt: time.Now().UTC()},
	}

	report := buildCreatorTokenRecurrence("Creator111", observed)
	if report.RecurringPatternCount != 0 {
		t.Fatalf("single-mint activity must not become cross-token recurrence: %+v", report.Patterns)
	}
	if report.Status != "no_cross_token_recurrence_observed" {
		t.Fatalf("status = %q", report.Status)
	}
}

func TestBuildCreatorTokenRecurrenceFindsVerifiedCounterpartyAndKindReuse(t *testing.T) {
	observed := newCreatorTokenObservedPathsReport("Creator222")
	observed.Paths = []creatorTokenObservedPath{
		{Mint: "MintA", Counterparty: "DexShared", CounterpartyKind: services.WalletEntityKindDEX, Signature: "sig-a", Slot: 201, LifecycleFate: services.ActorTokenFateActive},
		{Mint: "MintB", Counterparty: "DexShared", CounterpartyKind: services.WalletEntityKindDEX, Signature: "sig-b", Slot: 202, LifecycleFate: services.ActorTokenFateInactiveOrDead},
		{Mint: "MintC", Counterparty: "Bridge333", CounterpartyKind: services.WalletEntityKindBridge, Signature: "sig-c", Slot: 203},
	}

	report := buildCreatorTokenRecurrence("Creator222", observed)
	if report.Status != "verified_cross_token_movement_recurrence_observed" {
		t.Fatalf("status = %q", report.Status)
	}
	if report.DistinctMintsWithPaths != 3 {
		t.Fatalf("distinct mints = %d", report.DistinctMintsWithPaths)
	}
	if report.RecurringCounterpartyCount != 1 {
		t.Fatalf("recurring counterparties = %d", report.RecurringCounterpartyCount)
	}
	if report.RecurringEndpointKindCount != 1 {
		t.Fatalf("recurring endpoint kinds = %d", report.RecurringEndpointKindCount)
	}
	if report.RecurringPatternCount != 2 {
		t.Fatalf("pattern count = %d; patterns=%+v", report.RecurringPatternCount, report.Patterns)
	}
	for _, pattern := range report.Patterns {
		if pattern.DistinctMintCount < 2 || pattern.EvidenceCount < 2 {
			t.Fatalf("recurrence without cross-mint evidence: %+v", pattern)
		}
		if pattern.MaliciousnessClaimed {
			t.Fatalf("maliciousness claim emitted: %+v", pattern)
		}
	}
}

func TestBuildCreatorTokenRecurrenceUnknownEndpointDoesNotCreateTaxonomyPattern(t *testing.T) {
	observed := newCreatorTokenObservedPathsReport("Creator333")
	observed.Paths = []creatorTokenObservedPath{
		{Mint: "MintA", Counterparty: "UnknownA", CounterpartyKind: services.WalletEntityKindUnknown, Signature: "sig-a", Slot: 301},
		{Mint: "MintB", Counterparty: "UnknownB", CounterpartyKind: services.WalletEntityKindUnknown, Signature: "sig-b", Slot: 302},
	}

	report := buildCreatorTokenRecurrence("Creator333", observed)
	if report.RecurringEndpointKindCount != 0 {
		t.Fatalf("unknown taxonomy must not become recurrence: %+v", report.Patterns)
	}
	if value, _ := report.Policy["wrongdoing_claimed"].(bool); value {
		t.Fatal("wrongdoing claim must remain disabled")
	}
	if value, _ := report.Policy["neon_persistence"].(bool); value {
		t.Fatal("Neon persistence must remain disabled")
	}
}
