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
	for _, script := range []string{"koschei-english-runtime.js", "unified-scan-navigation.js"} {
		if strings.Count(body, script) != 1 {
			t.Fatalf("expected exactly one %s reference: %s", script, body)
		}
	}
	if strings.Contains(body, "arvis-social-render-v2-core.js") || strings.Contains(body, "arvis-complete-evidence-v3.js") || strings.Contains(body, "english-auth-presentation.js") {
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
		"koschei-english-runtime.js",
		"unified-scan-navigation.js",
	} {
		if strings.Count(second, script) != 1 {
			t.Fatalf("expected exactly one %s reference: %s", script, second)
		}
	}
}

func TestEnglishPublicHTMLInjectsAuthPresentationOverlayWithoutChangingAuthContract(t *testing.T) {
	html := `<!doctype html><html lang="tr"><body><form id="loginForm"></form><script src="/js/koschei-auth.js?v=33"></script></body></html>`
	first := string(rewritePublicHTMLToEnglish([]byte(html)))
	second := string(rewritePublicHTMLToEnglish([]byte(first)))

	if !strings.Contains(second, `<html lang="en">`) {
		t.Fatalf("auth page language was not rewritten: %s", second)
	}
	for _, script := range []string{"koschei-auth.js?v=33", "english-auth-presentation.js", "koschei-english-runtime.js", "unified-scan-navigation.js"} {
		if strings.Count(second, script) != 1 {
			t.Fatalf("auth page expected exactly one %s reference: %s", script, second)
		}
	}
	presentationIndex := strings.Index(second, "english-auth-presentation.js")
	runtimeIndex := strings.Index(second, "koschei-english-runtime.js")
	if presentationIndex < 0 || runtimeIndex < 0 || presentationIndex > runtimeIndex {
		t.Fatalf("auth presentation must run before the generic runtime: %s", second)
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
	if strings.Contains(response.Body.String(), "koschei-english-runtime.js") || strings.Contains(response.Body.String(), "unified-scan-navigation.js") {
		t.Fatal("public HTML scripts were injected into JSON")
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
