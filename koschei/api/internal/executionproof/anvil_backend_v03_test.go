package executionproof

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWaitForAnvilFailsClosedOnStartupTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := &evmRPCClient{url: server.URL, http: &http.Client{Timeout: 20 * time.Millisecond}}
	started := time.Now()
	err := waitForAnvil(context.Background(), client, 40*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "startup timeout") {
		t.Fatalf("error = %v, want startup timeout", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("startup timeout did not bound Anvil readiness wait")
	}
}

func TestWaitForAnvilHonorsContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := &evmRPCClient{url: server.URL, http: &http.Client{Timeout: 20 * time.Millisecond}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForAnvil(ctx, client, time.Second); err == nil {
		t.Fatal("cancelled context was accepted")
	}
}

type receiptRPCFixture struct {
	TransactionHash   string
	BlockHash         string
	BlockNumber       string
	Status            string
	GasUsed           string
	CumulativeGasUsed string
}

func receiptRPCServer(t *testing.T, fixture receiptRPCFixture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var req struct {
			JSONRPC string `json:"jsonrpc"`
			ID      int    `json:"id"`
			Method  string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode rpc request: %v", err)
		}
		if req.Method != "eth_getTransactionReceipt" {
			t.Fatalf("unexpected method %q", req.Method)
		}
		result := map[string]any{
			"transaction_hash":    fixture.TransactionHash,
			"block_hash":          fixture.BlockHash,
			"block_number":        fixture.BlockNumber,
			"status":              fixture.Status,
			"gas_used":            fixture.GasUsed,
			"cumulative_gas_used": fixture.CumulativeGasUsed,
			"contract_address":     nil,
			"logs":                 []any{},
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
}

func canonicalReceiptFixture() receiptRPCFixture {
	return receiptRPCFixture{
		TransactionHash:   "0x" + strings.Repeat("1", 64),
		BlockHash:         "0x" + strings.Repeat("2", 64),
		BlockNumber:       "0x10",
		Status:            "0x1",
		GasUsed:           "0x5208",
		CumulativeGasUsed: "0x5208",
	}
}

func TestTransactionReceiptDigestIsDeterministicForIdenticalEvidence(t *testing.T) {
	fixture := canonicalReceiptFixture()
	server := receiptRPCServer(t, fixture)
	defer server.Close()
	client := &evmRPCClient{url: server.URL, http: server.Client()}

	first, err := client.transactionReceiptDigest(context.Background(), fixture.TransactionHash)
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.transactionReceiptDigest(context.Background(), fixture.TransactionHash)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("identical receipt evidence produced nondeterministic digests: %s != %s", first, second)
	}
}

func TestTransactionReceiptDigestChangesWhenReceiptEvidenceMutates(t *testing.T) {
	base := canonicalReceiptFixture()
	server := receiptRPCServer(t, base)
	client := &evmRPCClient{url: server.URL, http: server.Client()}
	original, err := client.transactionReceiptDigest(context.Background(), base.TransactionHash)
	server.Close()
	if err != nil {
		t.Fatal(err)
	}

	mutated := base
	mutated.GasUsed = "0x5209"
	mutatedServer := receiptRPCServer(t, mutated)
	defer mutatedServer.Close()
	mutatedClient := &evmRPCClient{url: mutatedServer.URL, http: mutatedServer.Client()}
	changed, err := mutatedClient.transactionReceiptDigest(context.Background(), mutated.TransactionHash)
	if err != nil {
		t.Fatal(err)
	}
	if original == changed {
		t.Fatal("mutated receipt evidence did not change bound receipt digest")
	}
}

func TestTransactionReceiptDigestRejectsFailedExecution(t *testing.T) {
	fixture := canonicalReceiptFixture()
	fixture.Status = "0x0"
	server := receiptRPCServer(t, fixture)
	defer server.Close()
	client := &evmRPCClient{url: server.URL, http: server.Client()}
	if _, err := client.transactionReceiptDigest(context.Background(), fixture.TransactionHash); err == nil {
		t.Fatal("failed EVM execution produced an accepted receipt digest")
	}
}
