package services

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"koschei/api/internal/web3"
)

type solanaFailoverTransport struct {
	base http.RoundTripper
}

func init() {
	base := solanaRPCClient.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	solanaRPCClient.Transport = &solanaFailoverTransport{base: base}
}

func (t *solanaFailoverTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return solanaTransactionSingleflightRoundTrip(req, t.roundTripOnce)
}

func (t *solanaFailoverTransport) roundTripOnce(req *http.Request) (*http.Response, error) {
	method := strings.TrimSpace(req.Header.Get("X-Koschei-RPC-Method"))
	primary := req.URL.String()

	resp, err := t.roundTripGoverned(req)
	if err != nil || (resp != nil && (resp.StatusCode < 200 || resp.StatusCode >= 300)) {
		status := 0
		failureErr := err
		if resp != nil {
			status = resp.StatusCode
			if failureErr == nil {
				failureErr = fmt.Errorf("http status %d", status)
			}
		}
		if !solanaAdaptiveBatchDegradationStatus(req, status) {
			web3.LogRPCFailure(method, primary, status, failureErr)
		}
	}
	if !solanaFailoverEnabled() || !solanaFailoverRequired(resp, err) {
		return resp, err
	}
	fallbackRaw := web3.SolanaRPCFallbackURL("solana-mainnet")
	if strings.EqualFold(req.URL.Hostname(), web3.RPCProviderHost(fallbackRaw)) || req.GetBody == nil {
		return resp, err
	}
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 65536))
		_ = resp.Body.Close()
	}
	body, bodyErr := req.GetBody()
	if bodyErr != nil {
		web3.LogRPCFailure(method, primary, 0, bodyErr)
		return nil, bodyErr
	}
	fallbackURL, parseErr := url.Parse(fallbackRaw)
	if parseErr != nil {
		web3.LogRPCFailure(method, fallbackRaw, 0, parseErr)
		return nil, parseErr
	}
	fallbackReq := req.Clone(req.Context())
	fallbackReq.URL = fallbackURL
	fallbackReq.Host = ""
	fallbackReq.RequestURI = ""
	fallbackReq.Body = body
	fallbackReq.GetBody = req.GetBody
	fallbackResp, fallbackErr := t.roundTripGoverned(fallbackReq)
	if fallbackErr != nil || (fallbackResp != nil && (fallbackResp.StatusCode < 200 || fallbackResp.StatusCode >= 300)) {
		status := 0
		failureErr := fallbackErr
		if fallbackResp != nil {
			status = fallbackResp.StatusCode
			if failureErr == nil {
				failureErr = fmt.Errorf("http status %d", status)
			}
		}
		web3.LogRPCFailure(method, fallbackRaw, status, failureErr)
	}
	return fallbackResp, fallbackErr
}

func (t *solanaFailoverTransport) roundTripGoverned(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("solana rpc request is invalid")
	}
	endpoint := req.URL.String()
	if until, cooling := web3.SolanaRPCProviderCooldown(endpoint); cooling {
		return nil, fmt.Errorf("solana rpc provider cooling down until %s", until.UTC().Format("2006-01-02T15:04:05Z"))
	}
	if err := web3.WaitForSolanaRPCProviderSlot(req.Context(), endpoint); err != nil {
		return nil, err
	}
	resp, err := t.base.RoundTrip(req)
	if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
		delay := maxDuration(solanaRPC429Delay(0, resp.Header.Get("Retry-After")), solanaRPC429Cooldown())
		web3.DeferSolanaRPCProvider(endpoint, delay)
	}
	return resp, err
}

func solanaFailoverEnabled() bool {
	if raw := strings.TrimSpace(os.Getenv("SOLANA_RPC_FAILOVER_ENABLED")); raw != "" {
		enabled, parseErr := strconv.ParseBool(raw)
		return parseErr == nil && enabled
	}
	return strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production")
}

func solanaFailoverRequired(resp *http.Response, err error) bool {
	if err != nil || resp == nil {
		return true
	}
	switch resp.StatusCode {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func solanaAdaptiveBatchDegradationStatus(req *http.Request, status int) bool {
	if req == nil || req.Header.Get("X-Koschei-RPC-Adaptive-Batch") != "1" {
		return false
	}
	return status == http.StatusForbidden || status == http.StatusRequestEntityTooLarge
}
