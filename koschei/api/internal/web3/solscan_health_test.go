package web3

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSolscanUsageHealthUsesConfiguredKeyWithoutPromotingEvidence(t *testing.T) {
	oldURL := solscanUsageURL
	defer func() { solscanUsageURL = oldURL }()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("token") != "solscan-test-key" {
			t.Fatalf("token header=%q", r.Header.Get("token"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"remaining_cus":123,"usage_cus":10,"total_requests_24h":4,"success_rate_24h":100}}`)
	}))
	defer server.Close()
	solscanUsageURL = server.URL
	t.Setenv("SOLSCAN_API_KEY", "solscan-test-key")
	status, err := SolscanUsageHealth(context.Background(), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if status.RemainingCUs != 123 || status.TotalRequests24H != 4 {
		t.Fatalf("status=%#v", status)
	}
}
