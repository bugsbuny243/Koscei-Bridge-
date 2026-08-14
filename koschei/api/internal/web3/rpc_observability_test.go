package web3

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"
)

func TestRPCProviderHostDropsPathQueryAndCredentials(t *testing.T) {
	got := RPCProviderHost("https://user:secret@mainnet.helius-rpc.com/v0/key?api-key=hidden")
	if got != "mainnet.helius-rpc.com" {
		t.Fatalf("host=%q", got)
	}
	if RPCHTTPStatusClass(429) != "4xx" || RPCHTTPStatusClass(503) != "5xx" || RPCHTTPStatusClass(0) != "none" {
		t.Fatalf("unexpected status classes")
	}
	if label := RPCProviderLabel("https://user:secret@mainnet.helius-rpc.com/v0/key?api-key=hidden"); label != "helius" {
		t.Fatalf("provider label=%q, want helius", label)
	}
}

func TestLogRPCFailureNeverLeaksAPIKey(t *testing.T) {
	const secret = "super-secret-api-key"
	var out bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(previous)

	endpoint := "https://solana-mainnet.g.alchemy.com/v2/" + secret + "?api_key=" + secret
	LogRPCFailure("getTokenSupply", endpoint, 429, errors.New(`Post "`+endpoint+`": quota exhausted`))
	text := out.String()
	if strings.Contains(text, secret) {
		t.Fatalf("secret leaked: %s", text)
	}
	for _, expected := range []string{"provider=alchemy", "http_class=4xx", "status=429", "method=getTokenSupply", "error_class=request_failed"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q: %s", expected, text)
		}
	}
}

func TestLogRPCFailureDoesNotLogUnrecognizedInput(t *testing.T) {
	const injected = "attacker\nforged-log-entry"
	var out bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(previous)

	LogRPCFailure(injected, "https://unknown.example/"+injected, 500, errors.New(injected))
	if strings.Contains(out.String(), "attacker") || strings.Contains(out.String(), "forged") {
		t.Fatalf("unbounded input reached log: %s", out.String())
	}
}
