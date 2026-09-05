package handlers

import (
	"testing"

	"koschei/api/internal/services"
)

func TestSelectAddressAttributionCounterpartiesPrefersMostActive(t *testing.T) {
	rows := []addressFlowCounterparty{
		{Address: "WalletC", InboundTransfers: 1},
		{Address: "WalletA", InboundTransfers: 2, OutboundTransfers: 3},
		{Address: "WalletB", OutboundTransfers: 3},
	}
	selected := selectAddressAttributionCounterparties(rows, 2)
	if len(selected) != 2 {
		t.Fatalf("selected=%d", len(selected))
	}
	if selected[0].Address != "WalletA" || selected[1].Address != "WalletB" {
		t.Fatalf("selected=%#v", selected)
	}
}

func TestNewAddressAttributionReportDoesNotClaimPersonIdentity(t *testing.T) {
	report := newAddressAttributionReport("WalletABC")
	if report.Policy["real_person_identity_claim"] != false {
		t.Fatalf("policy=%#v", report.Policy)
	}
	if report.Policy["unknown_remains_unknown"] != true || report.Policy["provider_lookup_is_opt_in"] != true {
		t.Fatalf("policy=%#v", report.Policy)
	}
	if report.Policy["target_address_checked"] != true {
		t.Fatalf("policy=%#v", report.Policy)
	}
}

func TestAddressAttributionEntityFromLabelPreservesProviderProvenance(t *testing.T) {
	label := &services.WalletLabel{
		Address:  "WalletABC",
		Name:     "Known Wallet",
		Entity:   "Known Entity",
		Category: "Centralized Exchange",
		Labels:   []string{"exchange hot wallet"},
		Source:   "helius_identity",
	}
	entity := addressAttributionEntityFromLabel("WalletABC", label, addressFlowCounterparty{})
	if entity.Entity != "Known Entity" || entity.Source != "helius_identity" {
		t.Fatalf("entity=%#v", entity)
	}
	if entity.Verification != "provider_verified" || entity.IdentityScope != "known_onchain_entity_not_real_person_identity" {
		t.Fatalf("entity=%#v", entity)
	}
}
