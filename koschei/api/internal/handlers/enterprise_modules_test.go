package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildMEVRiskReportHighRisk(t *testing.T) {
	report := buildMEVRiskReport(mevAnalyzeRequest{InputAmountUSD: 25_000, SlippageBPS: 350, PoolLiquidityUSD: 500_000})
	if report.RiskScore < 70 {
		t.Fatalf("RiskScore = %d, want high risk >= 70", report.RiskScore)
	}
	if report.RiskLevel != "HIGH" {
		t.Fatalf("RiskLevel = %q, want HIGH", report.RiskLevel)
	}
	if report.EstimatedLossUSD <= 0 || !report.JitoTipUsed || report.MEVSavedUSD != report.EstimatedLossUSD {
		t.Fatalf("unexpected MEV economics: %+v", report)
	}
}

func TestSubmitJitoBundleUsesConfiguredEndpoint(t *testing.T) {
	var method string
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "result": "bundle-123"})
	}))
	defer server.Close()
	t.Setenv("JITO_BUNDLE_URL", server.URL)

	bundleID, status, err := (&Handler{}).submitJitoBundle(context.Background(), []string{"signed-tx"})
	if err != nil {
		t.Fatalf("submitJitoBundle() error = %v", err)
	}
	if method != http.MethodPost || bundleID != "bundle-123" || status != "submitted" {
		t.Fatalf("unexpected jito submission: method=%s bundle=%s status=%s", method, bundleID, status)
	}
	if payload["method"] != "sendBundle" {
		t.Fatalf("payload method = %v, want sendBundle", payload["method"])
	}
}

func TestLiquidityDrainScoreCritical(t *testing.T) {
	score := liquidityDrainScore(liquidityRadarRequest{ReserveDropPct: 55, RemovedLiquidity: 75_000, BlockDelay: 1})
	if score < 90 {
		t.Fatalf("liquidityDrainScore() = %d, want >= 90", score)
	}
}

func TestEmergencyLiquidityAlertPostsWebhook(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if payload["content"] == "" && payload["text"] == "" {
			t.Fatalf("payload missing content/text: %+v", payload)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	t.Setenv("DISCORD_WEBHOOK_URL", server.URL)
	t.Setenv("WHITEHAT_ALERT_ADDRESSES", "whitehat1,whitehat2")

	result := dispatchEmergencyLiquidityAlert(context.Background(), liquidityRadarRequest{PoolAddress: "pool", RemovedLiquidity: 100_000}, 100, "KRİTİK", 100_000)
	if !result.EmergencyMode || !result.DiscordSent || calls != 1 {
		t.Fatalf("unexpected emergency result: %+v calls=%d", result, calls)
	}
	if len(result.WhitehatAddresses) != 2 {
		t.Fatalf("whitehat addresses = %+v, want 2", result.WhitehatAddresses)
	}
}

func TestEmergencyLiquidityAlertIgnoresRequestWebhookDestination(t *testing.T) {
	operatorCalls := 0
	requestCalls := 0
	operatorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		operatorCalls++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer operatorServer.Close()
	requestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCalls++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer requestServer.Close()
	t.Setenv("DISCORD_WEBHOOK_URL", operatorServer.URL)

	result := dispatchEmergencyLiquidityAlert(context.Background(), liquidityRadarRequest{
		PoolAddress:    "pool",
		DiscordWebhook: requestServer.URL,
	}, 100, "CRITICAL", 100_000)
	if !result.DiscordSent || operatorCalls != 1 || requestCalls != 0 {
		t.Fatalf("unexpected dispatch: result=%+v operator=%d request=%d", result, operatorCalls, requestCalls)
	}
}

func TestWhitehatAddressesDeduplicateRequestAndEnv(t *testing.T) {
	t.Setenv("WHITEHAT_ALERT_ADDRESSES", "Alpha, Beta")
	got := whitehatAddresses([]string{"alpha", "Gamma"})
	if len(got) != 3 {
		t.Fatalf("whitehatAddresses() = %+v, want 3 unique addresses", got)
	}
}

func TestDAOProposalRiskScoreOutflow(t *testing.T) {
	score := daoProposalRiskScore(daoProposalRiskRequest{EstimatedOutflowUSD: 250_000, SignerCount: 6, RequiredSigners: 2, Instructions: []string{"transfer treasury", "set_authority"}})
	if score < 75 {
		t.Fatalf("daoProposalRiskScore() = %d, want >= 75", score)
	}
}
