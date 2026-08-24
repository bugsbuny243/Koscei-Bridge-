package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
)

// quotaResponseWriter is shared by the SaaS output reservation middleware. It
// records enough of the response to decide whether a reserved output should be
// consumed or refunded. No token-balance or KOSCH-tier state is involved.
const quotaDecisionBodyLimit = 4 << 20

type quotaResponseWriter struct {
	http.ResponseWriter
	status        int
	bodySample    []byte
	bodyTruncated bool
}

func (w *quotaResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *quotaResponseWriter) Write(body []byte) (int, error) {
	remaining := quotaDecisionBodyLimit - len(w.bodySample)
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

func (w *quotaResponseWriter) shouldConsumeQuota() bool {
	if w == nil || w.status < http.StatusOK || w.status >= http.StatusBadRequest {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(w.Header().Get("X-Koschei-Quota-Consume")), "false") {
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
