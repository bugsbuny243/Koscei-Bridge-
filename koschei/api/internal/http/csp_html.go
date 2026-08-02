package http

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"html"
	"mime"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxCSPHTMLBytes = 4 << 20

const (
	cspModeUndecided = iota
	cspModeHTML
	cspModePassthrough
)

var (
	cspNonceAttributePattern  = regexp.MustCompile(`(?is)\s+nonce\s*=`)
	cspScriptSourcePattern    = regexp.MustCompile(`(?is)\s+src\s*=`)
	cspInlineAttributePattern = regexp.MustCompile(`(?is)\s+(on[a-z0-9_-]+|style)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>]+))`)
	cspJavaScriptURLPattern   = regexp.MustCompile(`(?is)\b(?:href|src|action|formaction)\s*=\s*(?:"\s*javascript:|'\s*javascript:|javascript:)`)
)

type cspHTMLResponseWriter struct {
	writer       http.ResponseWriter
	request      *http.Request
	status       int
	mode         int
	committed    bool
	hijacked     bool
	body         bytes.Buffer
	bodyTooLarge bool
}

func newCSPHTMLResponseWriter(w http.ResponseWriter, r *http.Request) *cspHTMLResponseWriter {
	return &cspHTMLResponseWriter{writer: w, request: r, mode: cspModeUndecided}
}

func (w *cspHTMLResponseWriter) Header() http.Header {
	return w.writer.Header()
}

func (w *cspHTMLResponseWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 {
		w.writer.WriteHeader(status)
		return
	}
	if w.status != 0 || w.committed {
		return
	}
	w.status = status
}

func (w *cspHTMLResponseWriter) Write(p []byte) (int, error) {
	if w.hijacked {
		return 0, http.ErrHijacked
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.mode == cspModePassthrough {
		return w.writer.Write(p)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if !w.canTransformResponse(p) {
		if err := w.switchToPassthrough(); err != nil {
			return 0, err
		}
		return w.writer.Write(p)
	}
	w.mode = cspModeHTML
	if w.bodyTooLarge || w.body.Len()+len(p) > maxCSPHTMLBytes {
		w.bodyTooLarge = true
		return len(p), nil
	}
	return w.body.Write(p)
}

func (w *cspHTMLResponseWriter) canTransformResponse(firstChunk []byte) bool {
	if w.mode == cspModeHTML {
		return true
	}
	if w.request == nil || (w.request.Method != http.MethodGet && w.request.Method != http.MethodHead) {
		return false
	}
	if w.status == http.StatusNoContent || w.status == http.StatusNotModified || w.status == http.StatusPartialContent {
		return false
	}
	if w.request.Header.Get("Range") != "" || w.Header().Get("Content-Encoding") != "" {
		return false
	}
	contentType := strings.TrimSpace(w.Header().Get("Content-Type"))
	if contentType == "" {
		contentType = http.DetectContentType(firstChunk)
		w.Header().Set("Content-Type", contentType)
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.EqualFold(mediaType, "text/html") || strings.EqualFold(mediaType, "application/xhtml+xml")
}

func (w *cspHTMLResponseWriter) switchToPassthrough() error {
	if w.mode == cspModePassthrough {
		return nil
	}
	w.mode = cspModePassthrough
	w.Header().Set("Content-Security-Policy", koscheiBaseCSP())
	w.commit()
	if w.body.Len() > 0 {
		_, err := w.writer.Write(w.body.Bytes())
		w.body.Reset()
		return err
	}
	return nil
}

func (w *cspHTMLResponseWriter) commit() {
	if w.committed || w.hijacked {
		return
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.writer.WriteHeader(w.status)
	w.committed = true
}

func (w *cspHTMLResponseWriter) finish() {
	if w.committed || w.hijacked {
		return
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.mode != cspModeHTML {
		w.Header().Set("Content-Security-Policy", koscheiBaseCSP())
		w.commit()
		return
	}
	if w.bodyTooLarge {
		w.failClosed("secure HTML response exceeded the CSP transformation limit")
		return
	}
	nonce, err := newCSPNonce()
	if err != nil {
		w.failClosed("secure HTML nonce generation failed")
		return
	}
	body, scriptAttributeHashes, styleAttributeHashes, err := secureHTMLDocument(w.body.Bytes(), nonce)
	if err != nil {
		w.failClosed("secure HTML transformation failed")
		return
	}
	w.Header().Set("Content-Security-Policy", koscheiHTMLCSP(nonce, scriptAttributeHashes, styleAttributeHashes))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Del("Content-Encoding")
	w.Header().Del("ETag")
	w.Header().Del("Content-Range")
	w.Header().Del("Accept-Ranges")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.commit()
	if w.request == nil || w.request.Method != http.MethodHead {
		_, _ = w.writer.Write(body)
	}
}

func (w *cspHTMLResponseWriter) failClosed(message string) {
	body := []byte(message + "\n")
	w.status = http.StatusInternalServerError
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Security-Policy", koscheiBaseCSP())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Del("Content-Encoding")
	w.Header().Del("ETag")
	w.Header().Del("Last-Modified")
	w.Header().Del("Content-Range")
	w.Header().Del("Accept-Ranges")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.commit()
	if w.request == nil || w.request.Method != http.MethodHead {
		_, _ = w.writer.Write(body)
	}
}

func (w *cspHTMLResponseWriter) Flush() {
	_ = w.switchToPassthrough()
	if flusher, ok := w.writer.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *cspHTMLResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.writer.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	connection, readWriter, err := hijacker.Hijack()
	if err == nil {
		w.hijacked = true
	}
	return connection, readWriter, err
}

func (w *cspHTMLResponseWriter) Push(target string, options *http.PushOptions) error {
	pusher, ok := w.writer.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, options)
}

func (w *cspHTMLResponseWriter) Unwrap() http.ResponseWriter {
	return w.writer
}

func newCSPNonce() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(raw[:]), nil
}

func secureHTMLDocument(raw []byte, nonce string) ([]byte, []string, []string, error) {
	if nonce == "" {
		return nil, nil, nil, errors.New("CSP nonce is required")
	}
	if !utf8.Valid(raw) {
		return nil, nil, nil, errors.New("HTML response is not valid UTF-8")
	}
	document := string(raw)
	if cspJavaScriptURLPattern.MatchString(document) {
		return nil, nil, nil, errors.New("javascript URL attributes are not allowed")
	}
	scriptAttributeHashes, styleAttributeHashes := collectInlineAttributeHashes(document)
	document = nonceHTMLTags(document, "script", true, nonce)
	document = nonceHTMLTags(document, "style", false, nonce)
	return []byte(document), scriptAttributeHashes, styleAttributeHashes, nil
}

func nonceHTMLTags(document, tagName string, inlineOnly bool, nonce string) string {
	needle := "<" + strings.ToLower(tagName)
	lower := strings.ToLower(document)
	var output strings.Builder
	output.Grow(len(document) + 128)
	last := 0
	scan := 0
	for scan < len(document) {
		relative := strings.Index(lower[scan:], needle)
		if relative < 0 {
			break
		}
		start := scan + relative
		afterName := start + len(needle)
		if afterName < len(document) && !isHTMLTagNameBoundary(document[afterName]) {
			scan = afterName
			continue
		}
		end := findHTMLTagEnd(document, afterName)
		if end < 0 {
			break
		}
		tag := document[start : end+1]
		replacement := tag
		if !cspNonceAttributePattern.MatchString(tag) && (!inlineOnly || !cspScriptSourcePattern.MatchString(tag)) {
			replacement = addCSPNonceAttribute(tag, nonce)
		}
		output.WriteString(document[last:start])
		output.WriteString(replacement)
		last = end + 1
		scan = end + 1
	}
	if last == 0 {
		return document
	}
	output.WriteString(document[last:])
	return output.String()
}

func isHTMLTagNameBoundary(value byte) bool {
	return value == '>' || value == '/' || value == ' ' || value == '\t' || value == '\r' || value == '\n' || value == '\f'
}

func findHTMLTagEnd(document string, start int) int {
	var quote byte
	for index := start; index < len(document); index++ {
		current := document[index]
		if quote != 0 {
			if current == quote {
				quote = 0
			}
			continue
		}
		if current == '\'' || current == '"' {
			quote = current
			continue
		}
		if current == '>' {
			return index
		}
	}
	return -1
}

func addCSPNonceAttribute(tag, nonce string) string {
	index := strings.LastIndex(tag, ">")
	if index < 0 {
		return tag
	}
	prefix := tag[:index]
	suffix := tag[index:]
	if strings.HasSuffix(strings.TrimSpace(prefix), "/") {
		slash := strings.LastIndex(prefix, "/")
		return prefix[:slash] + ` nonce="` + nonce + `"` + prefix[slash:] + suffix
	}
	return prefix + ` nonce="` + nonce + `"` + suffix
}

func collectInlineAttributeHashes(document string) ([]string, []string) {
	scriptSet := map[string]struct{}{}
	styleSet := map[string]struct{}{}
	for _, match := range cspInlineAttributePattern.FindAllStringSubmatch(document, -1) {
		if len(match) < 5 {
			continue
		}
		value := match[2]
		if match[2] == "" && match[3] != "" {
			value = match[3]
		}
		if match[2] == "" && match[3] == "" {
			value = match[4]
		}
		hash := cspAttributeHash(html.UnescapeString(value))
		if strings.EqualFold(match[1], "style") {
			styleSet[hash] = struct{}{}
		} else {
			scriptSet[hash] = struct{}{}
		}
	}
	return sortedCSPHashes(scriptSet), sortedCSPHashes(styleSet)
}

func cspAttributeHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256-" + base64.StdEncoding.EncodeToString(digest[:])
}

func sortedCSPHashes(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func koscheiBaseCSP() string {
	return koscheiCSPDirectives("", nil, nil)
}

func koscheiHTMLCSP(nonce string, scriptAttributeHashes, styleAttributeHashes []string) string {
	return koscheiCSPDirectives(nonce, scriptAttributeHashes, styleAttributeHashes)
}

func koscheiCSPDirectives(nonce string, scriptAttributeHashes, styleAttributeHashes []string) string {
	scriptSources := []string{"'self'"}
	styleSources := []string{"'self'"}
	if nonce != "" {
		scriptSources = append(scriptSources, "'nonce-"+nonce+"'")
		styleSources = append(styleSources, "'nonce-"+nonce+"'")
	}
	scriptSources = append(scriptSources,
		"https://www.googletagmanager.com",
		"https://pagead2.googlesyndication.com",
		"https://*.googlesyndication.com",
		"https://*.doubleclick.net",
	)
	styleSources = append(styleSources, "https://fonts.googleapis.com")
	return strings.Join([]string{
		"default-src 'self'",
		"base-uri 'self'",
		"frame-ancestors 'none'",
		"object-src 'none'",
		"img-src 'self' data: blob: https://arweave.net https://ipfs.io https://gateway.pinata.cloud https://cdn.helius-rpc.com https://raw.githubusercontent.com https://pbs.twimg.com https://*.googleusercontent.com https://*.googlesyndication.com https://*.doubleclick.net https://*.google.com",
		"font-src 'self' data: https://fonts.gstatic.com",
		"style-src " + strings.Join(styleSources, " "),
		"style-src-attr " + cspAttributeDirective(styleAttributeHashes),
		"script-src " + strings.Join(scriptSources, " "),
		"script-src-attr " + cspAttributeDirective(scriptAttributeHashes),
		"connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com https://*.google-analytics.com https://*.googlesyndication.com https://*.doubleclick.net",
		"frame-src https://*.googlesyndication.com https://*.doubleclick.net https://*.google.com",
		"worker-src 'self' blob:",
		"media-src 'self' blob:",
		"manifest-src 'self'",
		"form-action 'self'",
		"upgrade-insecure-requests",
	}, "; ")
}

func cspAttributeDirective(hashes []string) string {
	if len(hashes) == 0 {
		return "'none'"
	}
	parts := []string{"'unsafe-hashes'"}
	for _, hash := range hashes {
		parts = append(parts, "'"+hash+"'")
	}
	return strings.Join(parts, " ")
}
