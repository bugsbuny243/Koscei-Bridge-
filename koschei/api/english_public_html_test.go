package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnglishPublicHTMLRewritesDocumentAndInjectsRuntime(t *testing.T) {
	handler := englishPublicHTML(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html lang="tr"><body><main>Sonuç</main></body></html>`))
	}))

	request := httptest.NewRequest(http.MethodGet, "/radar", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	body := response.Body.String()
	if !strings.Contains(body, `<html lang="en">`) {
		t.Fatalf("document language was not rewritten: %s", body)
	}
	if !strings.Contains(body, "koschei-english-runtime.js") {
		t.Fatalf("English runtime was not injected: %s", body)
	}
	if strings.Count(body, "koschei-english-runtime.js") != 1 {
		t.Fatalf("English runtime was injected more than once: %s", body)
	}
}

func TestEnglishPublicHTMLLeavesAPIJSONUntouched(t *testing.T) {
	handler := englishPublicHTML(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))

	request := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if got := response.Body.String(); got != `{"status":"ok"}` {
		t.Fatalf("API response changed: %s", got)
	}
	if strings.Contains(response.Body.String(), "koschei-english-runtime.js") {
		t.Fatal("English runtime was injected into JSON")
	}
}

func TestEnglishPublicHTMLLeavesStaticAssetsUntouched(t *testing.T) {
	handler := englishPublicHTML(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`console.log("ok")`))
	}))

	request := httptest.NewRequest(http.MethodGet, "/js/app.js", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if got := response.Body.String(); got != `console.log("ok")` {
		t.Fatalf("asset response changed: %s", got)
	}
}
