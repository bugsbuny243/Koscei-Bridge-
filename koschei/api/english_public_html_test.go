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
		_, _ = w.Write([]byte(`<!doctype html><html lang="tr"><body><main>Result</main></body></html>`))
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
	if strings.Contains(body, "arvis-social-render-v2-core.js") || strings.Contains(body, "arvis-complete-evidence-v3.js") || strings.Contains(body, "koschei-auth-english-overlay.js") {
		t.Fatalf("specialized extensions were injected into a generic page: %s", body)
	}
}

func TestEnglishPublicHTMLInjectsARVISResultExtensionsExactlyOnce(t *testing.T) {
	html := `<!doctype html><html lang="en"><body><script src="/js/arvis-premium-contract.js?v=1"></script><script src="/js/koschei-english-runtime.js?v=1"></script></body></html>`
	first := string(rewritePublicHTMLToEnglish([]byte(html)))
	second := string(rewritePublicHTMLToEnglish([]byte(first)))

	for _, script := range []string{
		"arvis-social-render-v2-core.js",
		"arvis-social-render-v2-cards.js",
		"arvis-social-render-v2-publish.js",
		"arvis-complete-evidence-v3.js",
	} {
		if strings.Count(second, script) != 1 {
			t.Fatalf("expected exactly one %s reference: %s", script, second)
		}
	}
	if strings.Count(second, "koschei-english-runtime.js") != 1 {
		t.Fatalf("English runtime was duplicated: %s", second)
	}
}

func TestEnglishPublicHTMLInjectsAuthPresentationOverlayWithoutChangingAuthContract(t *testing.T) {
	html := `<!doctype html><html lang="tr"><body><form id="loginForm"></form><script src="/js/koschei-auth.js?v=33"></script></body></html>`
	first := string(rewritePublicHTMLToEnglish([]byte(html)))
	second := string(rewritePublicHTMLToEnglish([]byte(first)))

	if !strings.Contains(second, `<html lang="en">`) {
		t.Fatalf("auth page language was not rewritten: %s", second)
	}
	if strings.Count(second, "koschei-auth.js?v=33") != 1 {
		t.Fatalf("frozen auth script contract changed: %s", second)
	}
	if strings.Count(second, "koschei-auth-english-overlay.js") != 1 {
		t.Fatalf("auth English overlay was not injected exactly once: %s", second)
	}
	if strings.Count(second, "koschei-english-runtime.js") != 1 {
		t.Fatalf("global English runtime was not injected exactly once: %s", second)
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
