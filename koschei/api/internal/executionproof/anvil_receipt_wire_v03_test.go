package executionproof

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestTransactionReceiptDecodesRPCWireWithoutChangingCanonicalShape(t *testing.T) {
	const txHash = "0x1111111111111111111111111111111111111111111111111111111111111111"
	const blockHash = "0x2222222222222222222222222222222222222222222222222222222222222222"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(receiptRPCResponseForTest(txHash, blockHash))
	}))
	defer server.Close()

	client := &evmRPCClient{url: server.URL, http: server.Client()}
	receipt, err := client.transactionReceipt(context.Background(), txHash)
	if err != nil {
		t.Fatalf("decode transaction receipt: %v", err)
	}
	if receipt.TransactionHash != txHash || receipt.BlockHash != blockHash {
		t.Fatalf("unexpected receipt identity: %#v", receipt)
	}
	if receipt.BlockNumber != "0x7" || receipt.Status != "0x1" || receipt.GasUsed != "0x5208" || receipt.CumulativeGasUsed != "0x5208" {
		t.Fatalf("unexpected canonical receipt fields: %#v", receipt)
	}

	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal canonical receipt: %v", err)
	}
	var canonical map[string]any
	if err := json.Unmarshal(encoded, &canonical); err != nil {
		t.Fatalf("decode canonical receipt: %v", err)
	}
	if _, ok := canonical["transaction_hash"]; !ok {
		t.Fatalf("canonical transaction_hash field missing: %s", encoded)
	}
	if _, ok := canonical["transactionHash"]; ok {
		t.Fatalf("RPC wire key leaked into canonical digest shape: %s", encoded)
	}
}

func TestRequireSuccessfulReceiptPollsPendingNullResult(t *testing.T) {
	const txHash = "0x3333333333333333333333333333333333333333333333333333333333333333"
	const blockHash = "0x4444444444444444444444444444444444444444444444444444444444444444"
	var calls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": nil})
			return
		}
		_ = json.NewEncoder(w).Encode(receiptRPCResponseForTest(txHash, blockHash))
	}))
	defer server.Close()

	client := &evmRPCClient{url: server.URL, http: server.Client()}
	if err := client.requireSuccessfulReceipt(context.Background(), txHash); err != nil {
		t.Fatalf("wait for successful receipt: %v", err)
	}
	if calls.Load() < 2 {
		t.Fatalf("pending receipt was not polled: calls=%d", calls.Load())
	}
}

func receiptRPCResponseForTest(txHash, blockHash string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"transactionHash":   txHash,
			"blockHash":         blockHash,
			"blockNumber":       "0x7",
			"status":            "0x1",
			"gasUsed":           "0x5208",
			"cumulativeGasUsed": "0x5208",
			"contractAddress":   nil,
			"logs":              []any{},
		},
	}
}
