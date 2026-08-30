package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const piLangDownloadTicketLifetime = 2 * time.Minute

// piLangMobileDownloadSurface fixes a Pi Browser / Android WebView limitation:
// fetching a ZIP into a JavaScript Blob does not reliably hand the file to the
// Android Download Manager. Licensed users instead receive a short-lived
// download lease and navigate directly to an attachment response. The lease is
// intentionally reusable only until expiry because Chromium/Android may probe
// or retry the same URL before the actual download begins.
func piLangMobileDownloadSurface(next http.Handler, staticDir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isPiLangHost(r.Host) {
			next.ServeHTTP(w, r)
			return
		}

		switch r.URL.Path {
		case "/", "/index.html":
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}
			servePiLangMobilePage(w, r, staticDir)
			return
		case "/api/pi/download-ticket":
			issuePiLangDownloadTicket(w, r, piLangDatabase())
			return
		case "/api/pi/download-file":
			consumePiLangDownloadTicket(w, r, piLangDatabase())
			return
		default:
			next.ServeHTTP(w, r)
		}
	})
}

func servePiLangMobilePage(w http.ResponseWriter, r *http.Request, staticDir string) {
	path := filepath.Join(staticDir, "lang.html")
	body, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "Koschei Lang page unavailable", http.StatusServiceUnavailable)
		return
	}

	const marker = "</body>"
	page := string(body)
	if !strings.Contains(page, marker) {
		http.Error(w, "Koschei Lang page invalid", http.StatusServiceUnavailable)
		return
	}
	page = strings.Replace(page, marker, piLangAndroidDownloadScript+"\n"+marker, 1)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = io.WriteString(w, page)
}

func ensurePiLangDownloadTicketSchema(r *http.Request, conn *sql.DB) error {
	if conn == nil {
		return errors.New("database unavailable")
	}
	if err := ensurePiLangSchema(r.Context(), conn); err != nil {
		return err
	}
	_, err := conn.ExecContext(r.Context(), `
CREATE TABLE IF NOT EXISTS pi_lang_download_tickets (
  ticket_hash TEXT PRIMARY KEY,
  user_uid TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pi_lang_download_tickets_uid ON pi_lang_download_tickets(user_uid);
CREATE INDEX IF NOT EXISTS idx_pi_lang_download_tickets_expiry ON pi_lang_download_tickets(expires_at);
`)
	return err
}

func issuePiLangDownloadTicket(w http.ResponseWriter, r *http.Request, conn *sql.DB) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if validPiLangPackageOrigin() == "" {
		http.Error(w, "licensed download package is not published yet", http.StatusServiceUnavailable)
		return
	}
	user, err := verifyPiLangUser(r)
	if err != nil {
		http.Error(w, "Pi authentication required", http.StatusUnauthorized)
		return
	}
	_, found, err := loadPiLangEntitlement(r.Context(), conn, user.UID)
	if err != nil {
		http.Error(w, "entitlement store unavailable", http.StatusServiceUnavailable)
		return
	}
	if !found {
		http.Error(w, "Koschei Lang license required", http.StatusPaymentRequired)
		return
	}
	if err := ensurePiLangDownloadTicketSchema(r, conn); err != nil {
		http.Error(w, "download ticket store unavailable", http.StatusServiceUnavailable)
		return
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "could not create download ticket", http.StatusServiceUnavailable)
		return
	}
	ticket := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(ticket))
	ticketHash := hex.EncodeToString(digest[:])
	expiresAt := time.Now().UTC().Add(piLangDownloadTicketLifetime)

	_, _ = conn.ExecContext(r.Context(), `DELETE FROM pi_lang_download_tickets WHERE expires_at < NOW() - INTERVAL '1 day'`)
	if _, err := conn.ExecContext(r.Context(), `
INSERT INTO pi_lang_download_tickets (ticket_hash, user_uid, expires_at)
VALUES ($1,$2,$3)
`, ticketHash, user.UID, expiresAt); err != nil {
		http.Error(w, "could not persist download ticket", http.StatusServiceUnavailable)
		return
	}

	payload := map[string]any{
		"url":        "/api/pi/download-file?ticket=" + url.QueryEscape(ticket),
		"filename":   piLangPackageFilename,
		"expires_at": expiresAt.Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(payload)
}

func consumePiLangDownloadTicket(w http.ResponseWriter, r *http.Request, conn *sql.DB) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := ensurePiLangDownloadTicketSchema(r, conn); err != nil {
		http.Error(w, "download ticket store unavailable", http.StatusServiceUnavailable)
		return
	}
	ticket := strings.TrimSpace(r.URL.Query().Get("ticket"))
	if len(ticket) < 40 || len(ticket) > 128 {
		http.Error(w, "invalid download ticket", http.StatusUnauthorized)
		return
	}
	if _, err := base64.RawURLEncoding.DecodeString(ticket); err != nil {
		http.Error(w, "invalid download ticket", http.StatusUnauthorized)
		return
	}
	digest := sha256.Sum256([]byte(ticket))
	ticketHash := hex.EncodeToString(digest[:])

	var userUID string
	err := conn.QueryRowContext(r.Context(), `
UPDATE pi_lang_download_tickets AS t
SET used_at = COALESCE(t.used_at, NOW())
FROM pi_lang_entitlements AS e
WHERE t.ticket_hash = $1
  AND t.expires_at > NOW()
  AND e.user_uid = t.user_uid
  AND e.status = 'active'
RETURNING t.user_uid
`, ticketHash).Scan(&userUID)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "download ticket expired", http.StatusUnauthorized)
		return
	}
	if err != nil || userUID == "" {
		http.Error(w, "download ticket unavailable", http.StatusServiceUnavailable)
		return
	}

	streamPiLangPackageAttachment(w, r)
}

func streamPiLangPackageAttachment(w http.ResponseWriter, r *http.Request) {
	origin := validPiLangPackageOrigin()
	if origin == "" {
		http.Error(w, "licensed download package is not published yet", http.StatusServiceUnavailable)
		return
	}
	packageURL := origin + "/" + url.PathEscape(piLangPackageFilename)
	method := http.MethodGet
	if r.Method == http.MethodHead {
		method = http.MethodHead
	}
	req, err := http.NewRequestWithContext(r.Context(), method, packageURL, nil)
	if err != nil {
		http.Error(w, "download origin unavailable", http.StatusBadGateway)
		return
	}
	req.Header.Set("Accept", "application/zip, application/octet-stream;q=0.9")
	if value := strings.TrimSpace(r.Header.Get("Range")); value != "" {
		req.Header.Set("Range", value)
	}
	if value := strings.TrimSpace(r.Header.Get("If-Range")); value != "" {
		req.Header.Set("If-Range", value)
	}
	resp, err := piLangPackageHTTPClient.Do(req)
	if err != nil {
		http.Error(w, "download origin unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		http.Error(w, "download package unavailable", http.StatusBadGateway)
		return
	}
	if resp.ContentLength > piLangPackageMaxBytes {
		http.Error(w, "download package exceeds safety limit", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, piLangPackageFilename))
	w.Header().Set("Cache-Control", "private, no-store, max-age=0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if value := strings.TrimSpace(resp.Header.Get("Accept-Ranges")); value != "" {
		w.Header().Set("Accept-Ranges", value)
	}
	if value := strings.TrimSpace(resp.Header.Get("Content-Range")); value != "" {
		w.Header().Set("Content-Range", value)
	}
	if resp.ContentLength >= 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", resp.ContentLength))
	}
	if resp.StatusCode == http.StatusPartialContent {
		w.WriteHeader(http.StatusPartialContent)
	}
	if r.Method == http.MethodHead {
		return
	}
	reader := io.Reader(resp.Body)
	if resp.ContentLength < 0 {
		reader = io.LimitReader(resp.Body, piLangPackageMaxBytes+1)
	}
	_, _ = io.Copy(w, reader)
}

const piLangAndroidDownloadScript = `<script>
(() => {
  const button = document.getElementById('pi-download');
  const status = document.getElementById('pi-status');
  if (!button || !status) return;

  function setTicketStatus(message, ok) {
    status.textContent = message;
    status.className = 'status' + (ok ? ' ok' : ' warn');
  }

  button.addEventListener('click', async (event) => {
    event.preventDefault();
    event.stopImmediatePropagation();
    button.disabled = true;
    try {
      if (!window.Pi) throw new Error('Pi SDK is unavailable. Open this page in Pi Browser.');
      const auth = await Pi.authenticate(['username', 'payments'], () => {});
      if (!auth || !auth.accessToken) throw new Error('Pi sign-in did not return an access token.');
      setTicketStatus('Preparing Android download…', false);
      const response = await fetch('/api/pi/download-ticket', {
        method: 'POST',
        headers: {'Authorization': 'Bearer ' + auth.accessToken},
        cache: 'no-store'
      });
      if (!response.ok) {
        const text = await response.text().catch(() => '');
        throw new Error(text || 'Could not create download link.');
      }
      const data = await response.json();
      if (!data || !data.url) throw new Error('Download link was not returned.');
      setTicketStatus('Opening Android download manager…', true);
      window.location.assign(data.url);
    } catch (error) {
      setTicketStatus(error && error.message ? error.message : String(error), false);
      button.disabled = false;
    }
  }, true);
})();
</script>`