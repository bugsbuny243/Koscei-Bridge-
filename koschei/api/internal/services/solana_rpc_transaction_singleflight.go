package services

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"koschei/api/internal/singleflight"
)

const (
	solanaTransactionSingleflightRequestInspectLimit = 64 << 10
	solanaTransactionSingleflightResponseLimit       = 8 << 20
)

var solanaTransactionFetchGroup singleflight.Group

type solanaTransactionResponseSnapshot struct {
	Status           string
	StatusCode       int
	Proto            string
	ProtoMajor       int
	ProtoMinor       int
	Header           http.Header
	Trailer          http.Header
	ContentLength    int64
	TransferEncoding []string
	Close            bool
	Uncompressed     bool
	Body             []byte
	EffectiveURL     string
}

// solanaTransactionSingleflightRoundTrip collapses identical in-flight
// getTransaction requests before they consume provider pacing/budget. It is an
// in-flight optimization only: completed responses are not cached.
func solanaTransactionSingleflightRoundTrip(req *http.Request, next func(*http.Request) (*http.Response, error)) (*http.Response, error) {
	if next == nil {
		return nil, fmt.Errorf("solana transaction transport is nil")
	}
	key, ok := solanaTransactionSingleflightKey(req)
	if !ok {
		return next(req)
	}

	value, err, _ := solanaTransactionFetchGroup.DoContext(req.Context(), key, func() (interface{}, error) {
		resp, callErr := next(req)
		if callErr != nil {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			return nil, callErr
		}
		return captureSolanaTransactionResponse(resp)
	})
	if err != nil {
		return nil, err
	}
	snapshot, ok := value.(*solanaTransactionResponseSnapshot)
	if !ok || snapshot == nil {
		return nil, fmt.Errorf("solana transaction singleflight returned an invalid response snapshot")
	}
	return snapshot.responseFor(req), nil
}

func solanaTransactionSingleflightKey(req *http.Request) (string, bool) {
	if req == nil || req.URL == nil || req.GetBody == nil {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(req.Header.Get("X-Koschei-RPC-Method")), "getTransaction") {
		return "", false
	}

	body, err := req.GetBody()
	if err != nil {
		return "", false
	}
	defer body.Close()
	payload, err := io.ReadAll(io.LimitReader(body, solanaTransactionSingleflightRequestInspectLimit+1))
	if err != nil || len(payload) == 0 || len(payload) > solanaTransactionSingleflightRequestInspectLimit {
		return "", false
	}
	var envelope struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil || envelope.Method != "getTransaction" {
		return "", false
	}

	// Hash the full endpoint and payload. Provider credentials may live in the
	// URL path/query, so the raw material is never retained or logged.
	material := req.URL.String() + "\n" + string(payload)
	digest := sha256.Sum256([]byte(material))
	return hex.EncodeToString(digest[:]), true
}

func captureSolanaTransactionResponse(resp *http.Response) (*solanaTransactionResponseSnapshot, error) {
	if resp == nil {
		return nil, fmt.Errorf("solana transaction transport returned nil response")
	}
	body := []byte(nil)
	if resp.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(resp.Body, solanaTransactionSingleflightResponseLimit+1))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if len(body) > solanaTransactionSingleflightResponseLimit {
			return nil, fmt.Errorf("solana transaction response exceeds %d bytes", solanaTransactionSingleflightResponseLimit)
		}
	}
	effectiveURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		effectiveURL = resp.Request.URL.String()
	}
	return &solanaTransactionResponseSnapshot{
		Status:           resp.Status,
		StatusCode:       resp.StatusCode,
		Proto:            resp.Proto,
		ProtoMajor:       resp.ProtoMajor,
		ProtoMinor:       resp.ProtoMinor,
		Header:           resp.Header.Clone(),
		Trailer:          resp.Trailer.Clone(),
		ContentLength:    resp.ContentLength,
		TransferEncoding: append([]string(nil), resp.TransferEncoding...),
		Close:            resp.Close,
		Uncompressed:     resp.Uncompressed,
		Body:             append([]byte(nil), body...),
		EffectiveURL:     effectiveURL,
	}, nil
}

func (s *solanaTransactionResponseSnapshot) responseFor(req *http.Request) *http.Response {
	effectiveReq := req
	if s.EffectiveURL != "" && req != nil {
		if parsed, err := url.Parse(s.EffectiveURL); err == nil {
			effectiveReq = req.Clone(req.Context())
			effectiveReq.URL = parsed
			effectiveReq.Host = ""
			effectiveReq.RequestURI = ""
		}
	}
	return &http.Response{
		Status:           s.Status,
		StatusCode:       s.StatusCode,
		Proto:            s.Proto,
		ProtoMajor:       s.ProtoMajor,
		ProtoMinor:       s.ProtoMinor,
		Header:           s.Header.Clone(),
		Body:             io.NopCloser(bytes.NewReader(s.Body)),
		ContentLength:    s.ContentLength,
		TransferEncoding: append([]string(nil), s.TransferEncoding...),
		Close:            s.Close,
		Uncompressed:     s.Uncompressed,
		Trailer:          s.Trailer.Clone(),
		Request:          effectiveReq,
	}
}
