package web3

import (
	"context"
	"errors"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// RPCProviderHost returns only the provider hostname. Paths, credentials and
// query strings are deliberately discarded so startup and failure logs cannot
// expose API keys.
func RPCProviderHost(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "unconfigured"
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || strings.TrimSpace(parsed.Hostname()) == "" {
		return "invalid-host"
	}
	return strings.ToLower(parsed.Hostname())
}

func RPCHTTPStatusClass(statusCode int) string {
	if statusCode <= 0 {
		return "none"
	}
	return strconv.Itoa(statusCode/100) + "xx"
}

// RPCProviderLabel returns a bounded label instead of attacker-controlled host
// text, so diagnostics cannot leak provider credentials or accept log payloads.
func RPCProviderLabel(rawURL string) string {
	host := RPCProviderHost(rawURL)
	switch {
	case host == "api.mainnet-beta.solana.com":
		return "solana"
	case host == "mainnet.helius-rpc.com" || strings.HasSuffix(host, ".helius-rpc.com"):
		return "helius"
	case strings.HasSuffix(host, ".g.alchemy.com"):
		return "alchemy"
	case strings.HasSuffix(host, ".quiknode.pro"):
		return "quicknode"
	case host == "127.0.0.1" || host == "localhost":
		return "local"
	case host == "unconfigured":
		return "unconfigured"
	case host == "invalid-host":
		return "invalid"
	default:
		return "other"
	}
}

func rpcMethodLabel(method string) string {
	switch strings.TrimSpace(method) {
	case "getAccountInfo":
		return "getAccountInfo"
	case "getBalance":
		return "getBalance"
	case "getBlockTime":
		return "getBlockTime"
	case "getMultipleAccounts":
		return "getMultipleAccounts"
	case "getSignaturesForAddress":
		return "getSignaturesForAddress"
	case "getTokenAccountBalance":
		return "getTokenAccountBalance"
	case "getTokenLargestAccounts":
		return "getTokenLargestAccounts"
	case "getTokenSupply":
		return "getTokenSupply"
	case "getTransaction":
		return "getTransaction"
	case "simulateTransaction":
		return "simulateTransaction"
	default:
		return "other"
	}
}

func rpcErrorClass(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return "network"
	}
	return "request_failed"
}

// LogRPCFailure emits only bounded diagnostic labels. Raw endpoints, method
// text and error strings are deliberately excluded.
func LogRPCFailure(method, endpoint string, statusCode int, err error) {
	log.Printf(
		"solana rpc failure method=%s provider=%s http_class=%s status=%d error_class=%s",
		rpcMethodLabel(method),
		RPCProviderLabel(endpoint),
		RPCHTTPStatusClass(statusCode),
		statusCode,
		rpcErrorClass(err),
	)
}
