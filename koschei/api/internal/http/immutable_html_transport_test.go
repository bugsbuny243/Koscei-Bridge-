package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeadersPreserveExplicitImmutableHeadersForStablePassthroughHTML(t *testing.T) {
	const (
		body = `<!doctype html><html><head><link rel="stylesheet" href="/css/dossier-print.css?v=1"></head><body>stable dossier</body></html>`
		etag = `"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"`
	)
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("ETag", etag)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("secured response writer does not expose safe passthrough flushing")
		}
		flusher.Flush()
		_, _ = w.Write([]byte(body))
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://tradepigloball.co/dossier/KD1-test", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := recorder.Header().Get("ETag"); got != etag {
		t.Fatalf("ETag = %q, want %q", got, etag)
	}
	if got := recorder.Body.String(); got != body {
		t.Fatalf("stable body changed: %q", got)
	}
	policy := recorder.Header().Get("Content-Security-Policy")
	if policy == "" || strings.Contains(policy, "'unsafe-inline'") || strings.Contains(policy, "'nonce-") {
		t.Fatalf("stable passthrough CSP is not strict and static: %s", policy)
	}
}
