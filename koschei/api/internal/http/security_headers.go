package http

import (
	"bufio"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const piBrowserFrameAncestors = "frame-ancestors 'self' https://app-cdn.minepi.com https://sandbox.minepi.com https://*.minepi.com https://*.pinet.com"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paddleCheckout := isPaddleCheckoutRequest(r)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("Content-Security-Policy", koscheiBaseCSP())
		if paddleCheckout {
			// The checkout page is intentionally the only public surface allowed to
			// load Paddle.js and Paddle's payment frame. It stays non-embeddable.
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
			w.Header().Set("Content-Security-Policy", paddleCheckoutCSP())
			w.Header().Set("Cache-Control", "no-store")
		} else {
			// Pi Browser/PiNet hosts the configured app inside Pi-controlled web
			// surfaces. X-Frame-Options: DENY and frame-ancestors 'none' make
			// Chromium reject that navigation with ERR_BLOCKED_BY_RESPONSE.
			// Keep clickjacking protection through a narrow CSP ancestor allowlist
			// instead of allowing arbitrary framing.
			w.Header().Del("X-Frame-Options")
		}
		if strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production") {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		if paddleCheckout {
			next.ServeHTTP(w, r)
			return
		}

		frameWriter := &piBrowserFrameResponseWriter{ResponseWriter: w}
		secured := newCSPHTMLResponseWriter(frameWriter, r)
		next.ServeHTTP(secured, r)
		secured.finish()
	})
}

type piBrowserFrameResponseWriter struct {
	http.ResponseWriter
}

func (w *piBrowserFrameResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *piBrowserFrameResponseWriter) WriteHeader(status int) {
	applyPiBrowserFramePolicy(w.Header())
	w.ResponseWriter.WriteHeader(status)
}

func (w *piBrowserFrameResponseWriter) Write(p []byte) (int, error) {
	applyPiBrowserFramePolicy(w.Header())
	return w.ResponseWriter.Write(p)
}

func (w *piBrowserFrameResponseWriter) Flush() {
	applyPiBrowserFramePolicy(w.Header())
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *piBrowserFrameResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (w *piBrowserFrameResponseWriter) Push(target string, options *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, options)
}

func (w *piBrowserFrameResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func applyPiBrowserFramePolicy(header http.Header) {
	if header == nil {
		return
	}
	header.Del("X-Frame-Options")
	policy := header.Get("Content-Security-Policy")
	if policy == "" {
		return
	}
	if strings.Contains(policy, "frame-ancestors 'none'") {
		policy = strings.Replace(policy, "frame-ancestors 'none'", piBrowserFrameAncestors, 1)
		header.Set("Content-Security-Policy", policy)
	}
}

func isPaddleCheckoutRequest(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	return path == "/paddle-checkout" || path == "/paddle-checkout.html"
}

func paddleCheckoutCSP() string {
	return strings.Join([]string{
		"default-src 'self'",
		"base-uri 'self'",
		"frame-ancestors 'none'",
		"object-src 'none'",
		"img-src 'self' data: https://paddle.com https://*.paddle.com",
		"font-src 'self' data:",
		"style-src 'self'",
		"script-src 'self' https://cdn.paddle.com",
		"script-src-attr 'none'",
		"connect-src 'self' https://paddle.com https://*.paddle.com",
		"frame-src https://paddle.com https://*.paddle.com",
		"worker-src 'self' blob:",
		"media-src 'self' blob:",
		"manifest-src 'self'",
		"form-action 'self' https://paddle.com https://*.paddle.com",
		"upgrade-insecure-requests",
	}, "; ")
}

func allowedCORSOrigin(origin string, allowed map[string]struct{}) string {
	canonical := canonicalCORSOrigin(origin, true)
	if canonical == "" {
		return ""
	}
	if _, ok := allowed[canonical]; ok {
		return canonical
	}
	return ""
}

func canonicalCORSOrigin(origin string, allowLoopbackHTTP bool) string {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	if origin == "" {
		return ""
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return ""
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	host := strings.ToLower(strings.TrimSpace(u.Host))
	switch scheme {
	case "https":
		return "https://" + host
	case "http":
		if allowLoopbackHTTP && isLoopbackCORSHost(u.Hostname()) {
			return "http://" + host
		}
	}
	return ""
}

func isLoopbackCORSHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "127.0.0.1" || host == "::1"
}
