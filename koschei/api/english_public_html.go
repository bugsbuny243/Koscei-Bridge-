package main

import (
	"bytes"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

const englishRuntimeScript = `<script src="/js/koschei-english-runtime.js?v=1" data-koschei-english-runtime="1"></script>`

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
	if strings.Contains(text, "koschei-english-runtime.js") {
		return []byte(text)
	}
	if index := strings.LastIndex(strings.ToLower(text), "</body>"); index >= 0 {
		text = text[:index] + englishRuntimeScript + text[index:]
	} else if index := strings.LastIndex(strings.ToLower(text), "</html>"); index >= 0 {
		text = text[:index] + englishRuntimeScript + text[index:]
	} else {
		text += englishRuntimeScript
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
