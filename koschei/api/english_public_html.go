package main

import (
	"bytes"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

const englishRuntimeScript = `<script src="/js/koschei-english-runtime.js?v=1" data-koschei-english-runtime="1"></script>`
const authEnglishOverlayScript = `<script src="/js/english-auth-presentation.js?v=2" data-koschei-auth-english-overlay="1"></script>`
const unifiedScanNavigationScript = `<script src="/js/unified-scan-navigation.js?v=1" data-koschei-unified-scan-navigation="1"></script>`

const arvisSocialRendererScripts = `<script src="/js/arvis-social-render-v2-core.js?v=2" data-arvis-social-v2="core"></script>
<script src="/js/arvis-social-render-v2-cards.js?v=2" data-arvis-social-v2="cards"></script>
<script src="/js/arvis-social-render-v2-publish.js?v=2" data-arvis-social-v2="publish"></script>`

const arvisCompleteEvidenceScript = `<script src="/js/arvis-complete-evidence-v3.js?v=3" data-arvis-complete-evidence-v3="1"></script>`

type bufferedHTMLResponse struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newBufferedHTMLResponse() *bufferedHTMLResponse {
	return &bufferedHTMLResponse{header: make(http.Header), status: http.StatusOK}
}

func (w *bufferedHTMLResponse) Header() http.Header { return w.header }

func (w *bufferedHTMLResponse) WriteHeader(status int) {
	if status <= 0 || w.status != http.StatusOK {
		return
	}
	w.status = status
}

func (w *bufferedHTMLResponse) Write(data []byte) (int, error) {
	return w.body.Write(data)
}

func englishPublicHTML(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !shouldRewritePublicHTML(r) {
			next.ServeHTTP(w, r)
			return
		}

		buffered := newBufferedHTMLResponse()
		next.ServeHTTP(buffered, r)
		body := buffered.body.Bytes()
		contentType := strings.ToLower(buffered.header.Get("Content-Type"))
		isHTML := strings.Contains(contentType, "text/html") || looksLikeHTML(body)
		if buffered.status < http.StatusOK || buffered.status >= http.StatusMultipleChoices || !isHTML {
			flushBufferedResponse(w, buffered, body)
			return
		}

		rewritten := rewritePublicHTMLToEnglish(body)
		flushBufferedResponse(w, buffered, rewritten)
	})
}

func shouldRewritePublicHTML(r *http.Request) bool {
	if r == nil || r.Method != http.MethodGet {
		return false
	}
	path := strings.ToLower(strings.TrimSpace(r.URL.Path))
	if path == "" || path == "/" {
		return true
	}
	if strings.HasPrefix(path, "/api/") || path == "/health" || path == "/ads.txt" || path == "/robots.txt" {
		return false
	}
	extension := filepath.Ext(path)
	return extension == "" || extension == ".html"
}

func looksLikeHTML(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	lower := bytes.ToLower(trimmed)
	return bytes.HasPrefix(lower, []byte("<!doctype html")) || bytes.HasPrefix(lower, []byte("<html"))
}

func rewritePublicHTMLToEnglish(body []byte) []byte {
	text := string(body)
	text = strings.Replace(text, `<html lang="tr">`, `<html lang="en">`, 1)
	text = strings.Replace(text, `<html lang='tr'>`, `<html lang="en">`, 1)
	if !strings.Contains(strings.ToLower(text), "<html lang=") {
		text = strings.Replace(text, "<html>", `<html lang="en">`, 1)
	}

	lower := strings.ToLower(text)
	extras := make([]string, 0, 5)
	hasPremiumContract := strings.Contains(lower, "arvis-premium-contract.js")
	hasAuthContract := strings.Contains(lower, "koschei-auth.js")
	if hasPremiumContract && !strings.Contains(lower, "arvis-social-render-v2-core.js") {
		extras = append(extras, arvisSocialRendererScripts)
	}
	if hasPremiumContract && !strings.Contains(lower, "arvis-complete-evidence-v3.js") {
		extras = append(extras, arvisCompleteEvidenceScript)
	}
	// Translate the frozen login/register DOM before the generic runtime makes
	// token-level substitutions. This preserves complete English sentences.
	if hasAuthContract && !strings.Contains(lower, "english-auth-presentation.js") {
		extras = append(extras, authEnglishOverlayScript)
	}
	if !strings.Contains(lower, "koschei-english-runtime.js") {
		extras = append(extras, englishRuntimeScript)
	}
	if !strings.Contains(lower, "unified-scan-navigation.js") {
		extras = append(extras, unifiedScanNavigationScript)
	}
	if len(extras) == 0 {
		return []byte(text)
	}

	injection := strings.Join(extras, "\n")
	if index := strings.LastIndex(strings.ToLower(text), "</body>"); index >= 0 {
		text = text[:index] + injection + text[index:]
	} else if index := strings.LastIndex(strings.ToLower(text), "</html>"); index >= 0 {
		text = text[:index] + injection + text[index:]
	} else {
		text += injection
	}
	return []byte(text)
}

func flushBufferedResponse(w http.ResponseWriter, buffered *bufferedHTMLResponse, body []byte) {
	for key, values := range buffered.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(buffered.status)
	_, _ = w.Write(body)
}
