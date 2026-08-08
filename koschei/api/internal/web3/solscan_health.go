package web3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const solscanUsageEndpoint = "https://pro-api.solscan.io/v2.0/monitor/usage"

var solscanUsageURL = solscanUsageEndpoint

type SolscanUsageStatus struct {
	RemainingCUs      float64 `json:"remaining_cus"`
	UsageCUs          float64 `json:"usage_cus"`
	TotalRequests24H  float64 `json:"total_requests_24h"`
	SuccessRate24H    float64 `json:"success_rate_24h"`
	SubscriptionEndAt string  `json:"end_date,omitempty"`
}

// SolscanUsageHealth is operational capability probing only. Solscan is an
// indexed third-party data source and this health response must never be
// promoted to VERIFIED on-chain evidence without canonical RPC confirmation.
func SolscanUsageHealth(ctx context.Context, client *http.Client) (SolscanUsageStatus, error) {
	apiKey := strings.TrimSpace(os.Getenv("SOLSCAN_API_KEY"))
	if apiKey == "" {
		return SolscanUsageStatus{}, errors.New("SOLSCAN_API_KEY is not configured")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, solscanUsageURL, nil)
	if err != nil {
		return SolscanUsageStatus{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("token", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return SolscanUsageStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return SolscanUsageStatus{}, fmt.Errorf("Solscan returned HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Success bool               `json:"success"`
		Data    SolscanUsageStatus `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return SolscanUsageStatus{}, err
	}
	if !payload.Success {
		return SolscanUsageStatus{}, errors.New("Solscan usage response was not successful")
	}
	return payload.Data, nil
}
