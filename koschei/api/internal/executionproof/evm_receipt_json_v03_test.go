package executionproof

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTransactionReceiptDecodesEthereumCamelCaseWireShape(t *testing.T) {
	txHash := "0x" + strings.Repeat("1", 64)
	blockHash := "0x" + strings.Repeat("2", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var req struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Method != "eth_getTransactionReceipt" {
			t.Fatalf("unexpected method %q", req.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result": map[string]any{
				"transactionHash":   txHash,
				"blockHash":         blockHash,
				"blockNumber":       "0x10",
				"status":            "0x1",
				"gasUsed":           "0x5208",
				"cumulativeGasUsed": "0x5208",
				"contractAddress":   nil,
				"logs":              []any{},
			},
		})
	}))
	defer server.Close()

	client := &evmRPCClient{url: server.URL, http: server.Client()}
	receipt, err := client.transactionReceipt(context.Background(), txHash)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.TransactionHash != txHash || receipt.BlockHash != blockHash || receipt.Status != "0x1" {
		t.Fatalf("receipt wire decode mismatch: %#v", receipt)
	}
	if _, err := client.transactionReceiptDigest(context.Background(), txHash); err != nil {
		t.Fatalf("camelCase receipt could not be bound: %v", err)
	}
}
