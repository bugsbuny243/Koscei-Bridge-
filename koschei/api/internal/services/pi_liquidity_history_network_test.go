package services

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestPiMainnetLiquidityHistoryDoesNotUseLegacyTestnetTransport(t *testing.T) {
	issuer := piTestPublicKey(0x71)
	target, ok := ParsePiRadarTarget("KSAFE:" + issuer)
	if !ok {
		t.Fatal("test Pi asset did not parse")
	}

	var legacyHits atomic.Int64
	legacy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		legacyHits.Add(1)
		http.Error(w, "legacy testnet transport must not be used", http.StatusInternalServerError)
	}))
	defer legacy.Close()

	mainnet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/liquidity_pools":
			fmt.Fprint(w, `{"_embedded":{"records":[{"id":"pool-main"}]}}`)
		case "/liquidity_pools/pool-main/operations":
			fmt.Fprintf(w, `{"_embedded":{"records":[{"id":"op-main","type":"liquidity_pool_deposit","transaction_hash":"tx-main","source_account":%q,"created_at":"2026-08-25T10:00:00Z","liquidity_pool_id":"pool-main","reserves_deposited":[{"asset":"native","amount":"5.0000000"},{"asset":%q,"amount":"10.0000000"}],"shares_received":"2.0000000"}]}}`, issuer, "KSAFE:"+issuer)
		default:
			http.NotFound(w, r)
		}
	}))
	defer mainnet.Close()

	t.Setenv("PI_HORIZON_URL", legacy.URL)
	t.Setenv("PI_MAINNET_HORIZON_URL", mainnet.URL)
	observation := collectPiLiquidityMovementObservationForNetwork(t.Context(), target, piMainnetNetwork)
	if legacyHits.Load() != 0 {
		t.Fatalf("Pi mainnet liquidity evidence touched legacy testnet transport %d time(s)", legacyHits.Load())
	}
	if observation.Source != "pi_mainnet_horizon_liquidity_operations" {
		t.Fatalf("source=%q", observation.Source)
	}
	if len(observation.Movements) != 1 || observation.Movements[0].TransactionHash != "tx-main" {
		t.Fatalf("mainnet movement evidence missing: %#v", observation.Movements)
	}
	if observation.Movements[0].EvidenceSource != observation.Source {
		t.Fatalf("movement source=%q observation source=%q", observation.Movements[0].EvidenceSource, observation.Source)
	}
}
