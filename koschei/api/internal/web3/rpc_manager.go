package web3

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

type RPCCaller interface {
	Call(ctx context.Context, method string, params any, target any) (string, error)
}

type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type RPCManager struct {
	client    HTTPDoer
	providers []RPCProviderConfig
	mu        sync.Mutex
	states    map[string]*RPCProviderState
}

type rpcEnvelope struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type rpcManagerStatusError struct {
	Status     int
	RetryAfter string
}

func (e *rpcManagerStatusError) Error() string {
	return fmt.Sprintf("rpc status %d", e.Status)
}

func NewRPCManager(client HTTPDoer, providers []RPCProviderConfig) *RPCManager {
	if client == nil {
		client = http.DefaultClient
	}
	ordered := append([]RPCProviderConfig(nil), providers...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Priority < ordered[j].Priority })
	states := make(map[string]*RPCProviderState, len(ordered))
	for i := range ordered {
		if ordered[i].MaxFailures <= 0 {
			ordered[i].MaxFailures = 5
		}
		if ordered[i].Cooldown <= 0 {
			ordered[i].Cooldown = time.Minute
		}
		if ordered[i].Timeout <= 0 {
			ordered[i].Timeout = 8 * time.Second
		}
		states[ordered[i].Name] = &RPCProviderState{Config: ordered[i], State: CircuitClosed}
	}
	return &RPCManager{client: client, providers: ordered, states: states}
}

func (m *RPCManager) Call(ctx context.Context, method string, params any, target any) (string, error) {
	var last error
	for _, p := range m.availableProviders(time.Now()) {
		if until, cooling := SolanaRPCProviderCooldown(p.URL); cooling {
			last = fmt.Errorf("solana rpc provider %s cooling down until %s", p.Name, until.UTC().Format(time.RFC3339))
			continue
		}
		if err := WaitForSolanaRPCProviderSlot(ctx, p.URL); err != nil {
			return "", err
		}
		if err := m.callProvider(ctx, p, method, params, target); err != nil {
			last = err
			if statusErr, ok := err.(*rpcManagerStatusError); ok && statusErr.Status == http.StatusTooManyRequests {
				DeferSolanaRPCProvider(p.URL, solanaRPC429Cooldown(statusErr.RetryAfter))
			}
			m.recordFailure(p, err)
			continue
		}
		m.recordSuccess(p)
		return p.Name, nil
	}
	if last == nil {
		last = errors.New("no rpc provider available")
	}
	return "", last
}

func (m *RPCManager) State(name string) (RPCProviderState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.states[name]
	if !ok {
		return RPCProviderState{}, false
	}
	return *st, true
}

func (m *RPCManager) availableProviders(now time.Time) []RPCProviderConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RPCProviderConfig, 0, len(m.providers))
	for _, p := range m.providers {
		st := m.states[p.Name]
		if st.State == CircuitOpen && now.Before(st.OpenedUntil) {
			continue
		}
		if st.State == CircuitOpen && !now.Before(st.OpenedUntil) {
			st.State = CircuitHalfOpen
		}
		out = append(out, p)
	}
	return out
}

func (m *RPCManager) recordFailure(p RPCProviderConfig, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.states[p.Name]
	st.Failures++
	st.LastError = err.Error()
	if st.Failures >= p.MaxFailures || st.State == CircuitHalfOpen {
		st.State = CircuitOpen
		st.OpenedUntil = time.Now().Add(p.Cooldown)
	}
}

func (m *RPCManager) recordSuccess(p RPCProviderConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.states[p.Name]
	st.Failures = 0
	st.LastError = ""
	st.State = CircuitClosed
	st.OpenedUntil = time.Time{}
	st.LastSuccess = time.Now()
}

func (m *RPCManager) callProvider(ctx context.Context, p RPCProviderConfig, method string, params any, target any) error {
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	payload, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		LogRPCFailure(method, p.URL, 0, err)
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, bytes.NewReader(payload))
	if err != nil {
		LogRPCFailure(method, p.URL, 0, err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		LogRPCFailure(method, p.URL, 0, err)
		return err
	}
	defer resp.Body.Close()
	actualEndpoint := p.URL
	if resp.Request != nil && resp.Request.URL != nil {
		actualEndpoint = resp.Request.URL.String()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := &rpcManagerStatusError{Status: resp.StatusCode, RetryAfter: resp.Header.Get("Retry-After")}
		LogRPCFailure(method, actualEndpoint, resp.StatusCode, err)
		return err
	}
	var envelope rpcEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		LogRPCFailure(method, actualEndpoint, resp.StatusCode, err)
		return err
	}
	if envelope.Error != nil {
		if envelope.Error.Code == http.StatusTooManyRequests {
			err := &rpcManagerStatusError{Status: http.StatusTooManyRequests}
			LogRPCFailure(method, actualEndpoint, resp.StatusCode, err)
			return err
		}
		err := fmt.Errorf("%s rpc error: %s", p.Name, envelope.Error.Message)
		LogRPCFailure(method, actualEndpoint, resp.StatusCode, err)
		return err
	}
	if err := json.Unmarshal(envelope.Result, target); err != nil {
		LogRPCFailure(method, actualEndpoint, resp.StatusCode, err)
		return err
	}
	return nil
}
