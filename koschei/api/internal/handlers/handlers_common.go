package handlers

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"koschei/api/internal/cache"
	"koschei/api/internal/jobs"
	"koschei/api/internal/web3"
)

type Handler struct {
	DB            *sql.DB
	DBRead        *sql.DB
	AdminPassword string
	Limiter       *rateLimiter
	DBInitError   string
	Cache         cache.Cache
	SolanaRPC     *web3.SolanaRPC
	JobStore      *jobs.Store
	JobQueue      jobs.Queue
	CourtClient   CourtNarrativeClient
}

func (h *Handler) dbAvailable(ctx context.Context) error {
	if h.DB == nil {
		if h.DBInitError != "" {
			return errors.New(h.DBInitError)
		}
		return errors.New("database handle is nil")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return h.DB.PingContext(ctx)
}

func isProduction() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production")
}

func (h *Handler) RequireDB(w http.ResponseWriter) bool {
	if err := h.dbAvailable(context.Background()); err != nil {
		if isProduction() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database unavailable"})
		} else {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database unavailable", "details": err.Error()})
		}
		return false
	}
	return true
}

func (h *Handler) DBPingError() error {
	if err := h.dbAvailable(context.Background()); err != nil {
		return fmt.Errorf("%w", err)
	}
	return nil
}

func isTransientDBError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	patterns := []string{"driver: bad connection", "connection reset", "connection closed", "broken pipe", "eof"}
	for _, p := range patterns {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIData(w http.ResponseWriter, status int, data any) {
	writeJSON(w, status, map[string]any{"success": true, "code": "OK", "data": data})
}

func decodeJSON(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	return json.NewDecoder(r.Body).Decode(dst)
}

func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	adminPassword := strings.TrimSpace(h.AdminPassword)
	if adminPassword == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return false
	}
	suppliedHash := sha256.Sum256([]byte(r.Header.Get("x-admin-password")))
	adminHash := sha256.Sum256([]byte(adminPassword))
	valid := subtle.ConstantTimeCompare(suppliedHash[:], adminHash[:]) == 1
	if !valid {
		if h.Limiter != nil && !h.Limiter.allow("admin-failed:"+clientIP(r), 10, 10*time.Minute) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
			return false
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return false
	}
	return true
}
