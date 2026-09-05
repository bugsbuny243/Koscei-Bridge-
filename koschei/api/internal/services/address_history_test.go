package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCollectAddressHistoryCompletesAcrossPages(t *testing.T) {
	pageCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var req struct {
			ID     int             `json:"id"`
			Method string          `json:"method"`
			Params []any           `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Method != "getSignaturesForAddress" {
			t.Fatalf("method=%s", req.Method)
		}
		pageCalls++
		w.Header().Set("Content-Type", "application/json")
		switch pageCalls {
		case 1:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[{"signature":"sig3","slot":30,"err":null,"blockTime":300},{"signature":"sig2","slot":20,"err":{"InstructionError":[0,"x"]},"blockTime":200}]}`)
		case 2:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[{"signature":"sig1","slot":10,"err":null,"blockTime":100}]}`)
		default:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[]}`)
		}
	}))
	defer server.Close()

	report, err := CollectAddressHistory(context.Background(), server.URL, "solana-mainnet", "WalletABC", AddressHistoryOptions{PageSize: 2, MaxPages: 4})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "complete" || !report.HistoryComplete {
		t.Fatalf("status=%s complete=%v", report.Status, report.HistoryComplete)
	}
	if report.SignaturesSeen != 3 || report.SuccessfulCount != 2 || report.FailedCount != 1 {
		t.Fatalf("seen=%d success=%d failed=%d", report.SignaturesSeen, report.SuccessfulCount, report.FailedCount)
	}
	if !report.FirstSeenAt.Equal(time.Unix(100, 0).UTC()) || !report.LastSeenAt.Equal(time.Unix(300, 0).UTC()) {
		t.Fatalf("first=%s last=%s", report.FirstSeenAt, report.LastSeenAt)
	}
	if report.NewestSignature != "sig3" || report.OldestSignature != "sig1" || report.NextCursor != "" {
		t.Fatalf("newest=%s oldest=%s next=%s", report.NewestSignature, report.OldestSignature, report.NextCursor)
	}
}

func TestCollectAddressHistoryReportsBoundedCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":[{"signature":"sig2","slot":20,"err":null,"blockTime":200},{"signature":"sig1","slot":10,"err":null,"blockTime":100}]}`)
	}))
	defer server.Close()

	report, err := CollectAddressHistory(context.Background(), server.URL, "solana-mainnet", "WalletABC", AddressHistoryOptions{PageSize: 2, MaxPages: 1})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "bounded" || report.HistoryComplete {
		t.Fatalf("status=%s complete=%v", report.Status, report.HistoryComplete)
	}
	if report.NextCursor != "sig1" {
		t.Fatalf("next_cursor=%s", report.NextCursor)
	}
	if len(report.Limitations) == 0 {
		t.Fatal("bounded history must explain the missing older range")
	}
}
