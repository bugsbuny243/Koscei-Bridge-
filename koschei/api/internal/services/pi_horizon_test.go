package services

import (
	"encoding/base32"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParsePiRadarTarget(t *testing.T) {
	issuer := piTestPublicKey(0x11)
	account, ok := ParsePiRadarTarget(issuer)
	if !ok || account.Kind != piRadarTargetKindAccount || account.Account != issuer {
		t.Fatalf("account target = %#v ok=%t", account, ok)
	}
	asset, ok := ParsePiRadarTarget("KSAFE:" + issuer)
	if !ok || asset.Kind != piRadarTargetKindAsset || asset.AssetCode != "KSAFE" || asset.Issuer != issuer {
		t.Fatalf("asset target = %#v ok=%t", asset, ok)
	}
	for _, invalid := range []string{"S" + strings.Repeat("A", 55), "TOO-LONG-CODE:" + issuer, "KSAFE:GNOTVALID", ""} {
		if parsed, ok := ParsePiRadarTarget(invalid); ok {
			t.Fatalf("invalid target %q parsed as %#v", invalid, parsed)
		}
	}
}

func TestPiHorizonSnapshotCollectsExactAssetEvidence(t *testing.T) {
	issuer := piTestPublicKey(0x21)
	holderA := piTestPublicKey(0x31)
	holderB := piTestPublicKey(0x41)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/accounts/"+issuer:
			fmt.Fprintf(w, `{"id":%q,"account_id":%q,"home_domain":"example.test","thresholds":{"low_threshold":1,"med_threshold":2,"high_threshold":3},"signers":[{"key":%q,"type":"ed25519_public_key","weight":1},{"key":%q,"type":"ed25519_public_key","weight":1}],"balances":[]}`, issuer, issuer, issuer, piTestPublicKey(0x22))
		case r.URL.Path == "/assets":
			fmt.Fprintf(w, `{"_embedded":{"records":[{"asset_code":"KSAFE","asset_issuer":%q,"num_accounts":2,"amount":"100.0000000"}]}}`, issuer)
		case r.URL.Path == "/accounts" && r.URL.Query().Get("asset") == "KSAFE:"+issuer:
			fmt.Fprintf(w, `{"_links":{"next":{"href":""}},"_embedded":{"records":[{"id":%q,"account_id":%q,"balances":[{"balance":"60.0000000","asset_type":"credit_alphanum4","asset_code":"KSAFE","asset_issuer":%q,"is_authorized":true}]},{"id":%q,"account_id":%q,"balances":[{"balance":"40.0000000","asset_type":"credit_alphanum4","asset_code":"KSAFE","asset_issuer":%q,"is_authorized":true}]}]}}`, holderA, holderA, issuer, holderB, holderB, issuer)
		case r.URL.Path == "/accounts/"+issuer+"/payments":
			fmt.Fprintf(w, `{"_embedded":{"records":[{"id":"1","type":"payment","transaction_hash":"tx-good","source_account":%q,"from":%q,"to":%q,"asset_type":"credit_alphanum4","asset_code":"KSAFE","asset_issuer":%q,"amount":"100.0000000","created_at":"2026-08-25T00:00:00Z"},{"id":"2","type":"payment","transaction_hash":"tx-wrong","source_account":%q,"from":%q,"to":%q,"asset_type":"credit_alphanum4","asset_code":"OTHER","asset_issuer":%q,"amount":"999.0000000","created_at":"2026-08-25T00:01:00Z"}]}}`, issuer, issuer, holderA, issuer, issuer, issuer, holderB, issuer)
		case r.URL.Path == "/accounts/"+issuer+"/operations":
			fmt.Fprint(w, `{"_embedded":{"records":[]}}`)
		case r.URL.Path == "/accounts/"+issuer+"/transactions":
			fmt.Fprint(w, `{"_embedded":{"records":[{"hash":"tx-good","ledger":123,"created_at":"2026-08-25T00:00:00Z","source_account":"x","operation_count":1,"successful":true}]}}`)
		case r.URL.Path == "/liquidity_pools":
			fmt.Fprint(w, `{"_embedded":{"records":[{"id":"pool-1","total_trustlines":"2"}]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("PI_HORIZON_URL", server.URL)
	target, _ := ParsePiRadarTarget("KSAFE:" + issuer)
	snapshot := collectPiHorizonSnapshot(t.Context(), target)
	if !snapshot.Available || !snapshot.AssetFound || snapshot.IssuerAccount == nil {
		t.Fatalf("snapshot unavailable: %#v", snapshot)
	}
	if !snapshot.HolderWindowComplete || len(snapshot.Holders) != 2 {
		t.Fatalf("holder window = complete:%t holders:%d errors:%v", snapshot.HolderWindowComplete, len(snapshot.Holders), snapshot.Errors)
	}
	if len(snapshot.IssuerPayments) != 1 || snapshot.IssuerPayments[0].TransactionHash != "tx-good" {
		t.Fatalf("exact-asset payment filter failed: %#v", snapshot.IssuerPayments)
	}
	if !snapshot.LiquidityQuerySuccessful || len(snapshot.LiquidityPools) != 1 {
		t.Fatalf("liquidity state not collected: %#v", snapshot.LiquidityPools)
	}
}

func TestAnalyzeArvisRadarsMultiChainDefaultsPiTargetToMainnetWithoutSigningGrade(t *testing.T) {
	issuer := piTestPublicKey(0x51)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/accounts/"+issuer:
			fmt.Fprintf(w, `{"id":%q,"account_id":%q,"thresholds":{"low_threshold":1,"med_threshold":1,"high_threshold":1},"signers":[{"key":%q,"type":"ed25519_public_key","weight":1}],"balances":[]}`, issuer, issuer, issuer)
		case r.URL.Path == "/assets":
			fmt.Fprintf(w, `{"_embedded":{"records":[{"asset_code":"KSAFE","asset_issuer":%q}]}}`, issuer)
		case r.URL.Path == "/accounts":
			fmt.Fprint(w, `{"_links":{"next":{"href":""}},"_embedded":{"records":[]}}`)
		case strings.HasSuffix(r.URL.Path, "/payments"), strings.HasSuffix(r.URL.Path, "/operations"), strings.HasSuffix(r.URL.Path, "/transactions"):
			fmt.Fprint(w, `{"_embedded":{"records":[]}}`)
		case r.URL.Path == "/liquidity_pools":
			fmt.Fprint(w, `{"_embedded":{"records":[]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("PI_MAINNET_HORIZON_URL", server.URL)
	analysis := AnalyzeArvisRadarsMultiChainContext(t.Context(), SecurityRadarRequest{Target: "KSAFE:" + issuer, Mode: "test"})
	if analysis.Bundle.Network != piMainnetNetwork || analysis.Bundle.Provider != piMainnetEvidenceSource {
		t.Fatalf("wrong adapter: network=%s provider=%s", analysis.Bundle.Network, analysis.Bundle.Provider)
	}
	if len(analysis.Arms) != 14 {
		t.Fatalf("arm count=%d", len(analysis.Arms))
	}
	if analysis.Final.Signed || analysis.Final.Grade != "-" || analysis.Final.RiskLevel != "unknown" {
		t.Fatalf("Pi evidence fabricated a grade: %#v", analysis.Final)
	}
	if analysis.Bundle.PumpSybilRadar.RiskLevel != "not_applicable" || analysis.Bundle.RaydiumPoolGuardian.RiskLevel != "not_applicable" {
		t.Fatalf("Solana-only arms were not marked N/A")
	}
}

func TestAnalyzeArvisRadarsMultiChainSupportsExplicitPiTestnet(t *testing.T) {
	issuer := piTestPublicKey(0x61)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/accounts/"+issuer {
			fmt.Fprintf(w, `{"id":%q,"account_id":%q,"thresholds":{"low_threshold":1,"med_threshold":1,"high_threshold":1},"signers":[{"key":%q,"type":"ed25519_public_key","weight":1}],"balances":[]}`, issuer, issuer, issuer)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	t.Setenv("PI_TESTNET_HORIZON_URL", server.URL)
	analysis := AnalyzeArvisRadarsMultiChainContext(t.Context(), SecurityRadarRequest{Target: issuer, Network: "pi-testnet", Mode: "test"})
	if analysis.Bundle.Network != piTestnetNetwork || analysis.Bundle.Provider != piTestnetEvidenceSourceV2 {
		t.Fatalf("wrong testnet adapter: network=%s provider=%s", analysis.Bundle.Network, analysis.Bundle.Provider)
	}
	if analysis.Final.Signed {
		t.Fatal("testnet evidence unexpectedly signed a grade")
	}
}

func TestNormalizePiRadarNetwork(t *testing.T) {
	cases := map[string]string{"pi": piMainnetNetwork, "pi-mainnet": piMainnetNetwork, "pinet-mainnet": piMainnetNetwork, "pi-testnet": piTestnetNetwork, "pinet-testnet": piTestnetNetwork}
	for input, expected := range cases {
		actual, ok := NormalizePiRadarNetwork(input)
		if !ok || actual != expected {
			t.Fatalf("NormalizePiRadarNetwork(%q) = %q,%t want %q,true", input, actual, ok, expected)
		}
	}
	if _, ok := NormalizePiRadarNetwork("solana-mainnet"); ok {
		t.Fatal("Solana network was accepted as Pi")
	}
}

func TestPiMainnetHorizonDoesNotReuseLegacyTestnetOverride(t *testing.T) {
	t.Setenv("PI_HORIZON_URL", "http://127.0.0.1:1")
	t.Setenv("PI_MAINNET_HORIZON_URL", "")
	base, err := piHorizonBaseURLForNetwork(piMainnetNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if base.String() != piDefaultMainnetHorizonURL {
		t.Fatalf("mainnet base = %s want %s", base.String(), piDefaultMainnetHorizonURL)
	}
}

func TestPiHorizonURLRejectsPublicHTTP(t *testing.T) {
	t.Setenv("PI_HORIZON_URL", "http://example.com")
	if _, err := piHorizonBaseURL(); err == nil {
		t.Fatal("public HTTP Pi Horizon URL was accepted")
	}
	t.Setenv("PI_MAINNET_HORIZON_URL", "http://example.com")
	if _, err := piHorizonBaseURLForNetwork(piMainnetNetwork); err == nil {
		t.Fatal("public HTTP Pi mainnet Horizon URL was accepted")
	}
}

func piTestPublicKey(fill byte) string {
	raw := make([]byte, 35)
	raw[0] = 6 << 3
	for index := 1; index < 33; index++ {
		raw[index] = fill
	}
	checksum := piCRC16XModem(raw[:33])
	raw[33] = byte(checksum)
	raw[34] = byte(checksum >> 8)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
}
