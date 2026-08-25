package services

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPiFundingOriginRowMapsCreationAndNativePayment(t *testing.T) {
	creation, ok := piFundingOriginRow("GWALLET", piFundingHorizonOperation{
		ID:              "op-create",
		Type:            "create_account",
		TransactionHash: "tx-create",
		SourceAccount:   "GFUNDER",
		Funder:          "GFUNDER",
		Account:         "GWALLET",
		StartingBalance: "12.5000000",
		CreatedAt:       "2026-08-25T08:00:00Z",
	}, true)
	if !ok {
		t.Fatal("expected account-creation funding evidence")
	}
	if creation.Relation != piFundingCreationRelation || creation.SourceAccount != "GFUNDER" || creation.Amount != "12.5000000" || creation.TransactionHash != "tx-create" {
		t.Fatalf("unexpected creation funding row: %#v", creation)
	}

	payment, ok := piFundingOriginRow("GWALLET", piFundingHorizonOperation{
		ID:              "op-payment",
		Type:            "payment",
		TransactionHash: "tx-payment",
		SourceAccount:   "GFUNDER2",
		From:            "GFUNDER2",
		To:              "GWALLET",
		AssetType:       "native",
		Amount:          "3.2500000",
		CreatedAt:       "2026-08-25T08:05:00Z",
	}, false)
	if !ok {
		t.Fatal("expected native-payment funding evidence")
	}
	if payment.Relation != piFundingPaymentRelation || payment.SourceAccount != "GFUNDER2" || payment.HistoryComplete {
		t.Fatalf("unexpected payment funding row: %#v", payment)
	}
}

func TestPiFundingOriginRowRejectsUnrelatedOperations(t *testing.T) {
	cases := []piFundingHorizonOperation{
		{Type: "create_account", TransactionHash: "tx", Account: "GOTHER", Funder: "GFUNDER"},
		{Type: "payment", TransactionHash: "tx", To: "GWALLET", From: "GFUNDER", AssetType: "credit_alphanum4"},
		{Type: "payment", TransactionHash: "tx", To: "GOTHER", From: "GFUNDER", AssetType: "native"},
		{Type: "manage_sell_offer", TransactionHash: "tx", SourceAccount: "GFUNDER"},
		{Type: "create_account", Account: "GWALLET", Funder: "GFUNDER"},
	}
	for index, operation := range cases {
		if row, ok := piFundingOriginRow("GWALLET", operation, true); ok {
			t.Fatalf("case %d unexpectedly mapped: %#v", index, row)
		}
	}
}

func TestSelectPiFundingCandidatesUsesLargestPositiveBalances(t *testing.T) {
	holders := []piHolderObservation{
		{Account: "GLOW", Balance: 1},
		{Account: "GHIGH", Balance: 100},
		{Account: "GMID", Balance: 10},
		{Account: "GZERO", Balance: 0},
		{Account: "GHIGH", Balance: 100},
	}
	got := selectPiFundingCandidates(holders)
	if len(got) != 3 {
		t.Fatalf("expected three unique positive-balance candidates, got %#v", got)
	}
	if got[0].Account != "GHIGH" || got[1].Account != "GMID" || got[2].Account != "GLOW" {
		t.Fatalf("unexpected candidate order: %#v", got)
	}
}

func TestPiFundingSharedSourceGroupsRequireRepeatedSource(t *testing.T) {
	groups, largest := piFundingSharedSourceGroups([]PiFundingOriginRow{
		{Wallet: "G1", SourceAccount: "GFUND"},
		{Wallet: "G2", SourceAccount: "GFUND"},
		{Wallet: "G3", SourceAccount: "GOTHER"},
	})
	if len(groups) != 1 || largest != 2 {
		t.Fatalf("unexpected groups: %#v largest=%d", groups, largest)
	}
	if groups[0].SourceAccount != "GFUND" || strings.Join(groups[0].Wallets, ",") != "G1,G2" {
		t.Fatalf("unexpected shared source group: %#v", groups[0])
	}
}

func TestPiFundingBridgeCollectsTransactionBackedSharedSourceEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/accounts":
			_, _ = io.WriteString(w, `{"_links":{"next":{"href":""}},"_embedded":{"records":[{"account_id":"G1","balances":[{"balance":"100","asset_type":"credit_alphanum4","asset_code":"ABC","asset_issuer":"GISSUER","is_authorized":true}]},{"account_id":"G2","balances":[{"balance":"80","asset_type":"credit_alphanum4","asset_code":"ABC","asset_issuer":"GISSUER","is_authorized":true}]},{"account_id":"G3","balances":[{"balance":"60","asset_type":"credit_alphanum4","asset_code":"ABC","asset_issuer":"GISSUER","is_authorized":true}]}]}}`)
		case "/accounts/G1/operations":
			_, _ = io.WriteString(w, `{"_embedded":{"records":[{"id":"op1","type":"create_account","transaction_hash":"tx1","source_account":"GFUND","funder":"GFUND","account":"G1","starting_balance":"10","created_at":"2026-08-25T08:00:00Z"}]}}`)
		case "/accounts/G2/operations":
			_, _ = io.WriteString(w, `{"_embedded":{"records":[{"id":"op2","type":"payment","transaction_hash":"tx2","source_account":"GFUND","from":"GFUND","to":"G2","asset_type":"native","amount":"5","created_at":"2026-08-25T08:01:00Z"}]}}`)
		case "/accounts/G3/operations":
			_, _ = io.WriteString(w, `{"_embedded":{"records":[{"id":"op3","type":"create_account","transaction_hash":"tx3","source_account":"GOTHER","funder":"GOTHER","account":"G3","starting_balance":"2","created_at":"2026-08-25T08:02:00Z"}]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("PI_HORIZON_URL", server.URL)

	analysis := ArvisAnalysis{
		Bundle: SecurityRadarBundle{Metadata: map[string]any{}},
		Arms: []SecurityRadarVerdict{{
			Module:   "Funding Cluster Detector",
			ModuleID: ModuleFundingClusterDetector,
			Signals:  map[string]any{"evidence_status": "insufficient_evidence", "arm_evidence_available": false},
			Evidence: []string{"Pi funding evidence pending."},
		}},
		Graph: SecurityRadarVerdict{Signals: map[string]any{"nodes": []map[string]any{}, "edges": []map[string]any{}}, Evidence: []string{}},
	}
	target := PiRadarTarget{Kind: piRadarTargetKindAsset, Raw: "ABC:GISSUER", AssetCode: "ABC", Issuer: "GISSUER"}
	got := enrichPiFundingClusterEvidenceFromHorizon(t.Context(), analysis, target)

	observation, ok := got.Bundle.Metadata["pi_funding_cluster"].(PiFundingClusterObservation)
	if !ok {
		t.Fatalf("missing funding observation: %#v", got.Bundle.Metadata)
	}
	if observation.FundingRowsObserved != 3 || observation.SharedSourceGroupCount != 1 || observation.LargestSharedSourceGroup != 2 {
		t.Fatalf("unexpected funding observation: %#v", observation)
	}
	if len(got.Arms) != 1 || got.Arms[0].Signals["evidence_status"] != "observed" || got.Arms[0].Signals["same_controller_claim"] != false {
		t.Fatalf("funding arm did not preserve evidence-only boundary: %#v", got.Arms)
	}
	edges := piGraphMaps(got.Graph.Signals["edges"])
	if len(edges) != 3 {
		t.Fatalf("expected three graph funding edges, got %#v", edges)
	}
	joined := strings.ToLower(strings.Join(got.Arms[0].Evidence, " "))
	if !strings.Contains(joined, "not proof of common control") {
		t.Fatalf("missing identity/control limitation: %s", joined)
	}
}
