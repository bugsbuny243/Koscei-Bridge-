package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func trustedJupiterGETJSON(ctx context.Context, client *http.Client, endpoint string, out any) error {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("invalid Jupiter endpoint")
	}
	if err := validateJupiterReadOnlyEndpointTransport(parsed); err != nil {
		return err
	}
	if strings.EqualFold(parsed.Hostname(), "api.jup.ag") && strings.TrimSpace(os.Getenv("JUPITER_API_KEY")) == "" {
		return errJupiterAPIKeyUnavailable
	}
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Koschei-Jupiter-Context/1.0")
	if apiKey := jupiterAPIKeyForQuoteEndpoint(parsed.String()); apiKey != "" {
		req.Header.Set("x-api-key", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Jupiter HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(out)
}

func validatedReadOnlyJupiterPriceEndpoint(raw string) (*url.URL, error) {
	endpoint, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || endpoint.Host == "" {
		return nil, fmt.Errorf("invalid Jupiter price endpoint")
	}
	if err := validateJupiterReadOnlyEndpointTransport(endpoint); err != nil {
		return nil, err
	}
	path := strings.TrimRight(endpoint.Path, "/")
	if !strings.HasSuffix(path, "/price") && !strings.HasSuffix(path, "/price/v3") {
		return nil, fmt.Errorf("Jupiter endpoint rejected: only a read-only price path is allowed")
	}
	return endpoint, nil
}
