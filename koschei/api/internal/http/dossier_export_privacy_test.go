package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPrivateDossierExportScrubsPublicDiscoveryHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Location", "/dossier/KD1-example")
		w.Header().Set("Link", `</dossier/KD1-example>; rel="alternate"`)
		w.Header().Set("X-Koschei-Public-Dossier", "/dossier/KD1-example")
		w.Header().Set("ETag", `"sha256:example"`)
		w.Header().Set("X-Koschei-Case-Ref", "KD1-example")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	recorder := httptest.NewRecorder()
	privateDossierExport(next).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/dossier/example", nil))

	for _, name := range []string{"Content-Location", "Link", "X-Koschei-Public-Dossier"} {
		if value := recorder.Header().Get(name); value != "" {
			t.Fatalf("private export leaked public discovery header %s=%q", name, value)
		}
	}
	if got := recorder.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("private export cache policy = %q", got)
	}
	if got := recorder.Header().Get("X-Koschei-Dossier-Visibility"); got != "private-export" {
		t.Fatalf("private export visibility = %q", got)
	}
	if recorder.Header().Get("ETag") == "" || recorder.Header().Get("X-Koschei-Case-Ref") == "" {
		t.Fatal("private export lost immutable identity headers")
	}
}
