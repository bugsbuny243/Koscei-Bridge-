package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
)

const outputDecisionBodyLimit = 4 << 20

type outputResponseWriter struct {
	http.ResponseWriter
	status        int
	bodySample    []byte
	bodyTruncated bool
}

func (w *outputResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *outputResponseWriter) Write(body []byte) (int, error) {
	remaining := outputDecisionBodyLimit - len(w.bodySample)
	if remaining > 0 {
		if len(body) <= remaining {
			w.bodySample = append(w.bodySample, body...)
		} else {
			w.bodySample = append(w.bodySample, body[:remaining]...)
			w.bodyTruncated = true
		}
	} else if len(body) > 0 {
		w.bodyTruncated = true
	}
	return w.ResponseWriter.Write(body)
}

func (w *outputResponseWriter) shouldConsumeOutput() bool {
	if w == nil || w.status < http.StatusOK || w.status >= http.StatusBadRequest {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(w.Header().Get("X-Koschei-Output-Consume")), "false") ||
		strings.EqualFold(strings.TrimSpace(w.Header().Get("X-Koschei-Quota-Consume")), "false") {
		return false
	}
	if w.bodyTruncated || len(w.bodySample) == 0 {
		return true
	}
	var envelope struct {
		Charged *bool `json:"charged"`
	}
	if err := json.Unmarshal(w.bodySample, &envelope); err == nil && envelope.Charged != nil {
		return *envelope.Charged
	}
	return true
}
