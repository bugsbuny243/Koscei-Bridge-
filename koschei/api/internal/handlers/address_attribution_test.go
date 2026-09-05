package handlers

import "testing"

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
}
