package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"koschei/api/internal/cache"
	"koschei/api/internal/handlers"
	apihttp "koschei/api/internal/http"
	"koschei/api/internal/jobs"
	"koschei/api/internal/services"
	"koschei/api/internal/web3"
)

const (
	httpReadHeaderTimeout = 5 * time.Second
	httpReadTimeout       = 15 * time.Second
	httpWriteTimeout      = 10 * time.Minute
	httpIdleTimeout       = 60 * time.Second
	httpShutdownTimeout   = 15 * time.Second
)

func main() {
	log.Printf("koschei api starting")
	if missing := services.MissingProductionSecurityEnv(); len(missing) > 0 {
		log.Fatalf("CRITICAL: missing required production security env vars: %s", strings.Join(missing, ", "))
	}

	appCtx, stopApp := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopApp()

	// Architecture boundary: Koschei Web3 is stateless with respect to application
	// blockchain/radar/evidence data. Neon is an authentication system only.
	// This process intentionally never reads DATABASE_URL, never opens PostgreSQL,
	// and never starts database-backed radar, telemetry, job, alert or webhook workers.
	const dbInitError = "application persistence disabled by architecture"
	log.Printf("stateless Web3 runtime enabled: application PostgreSQL persistence is not part of this process")

	appCache := buildCache()
	defer appCache.Close()
	solanaRPC := web3.NewSolanaRPC(appCache)
	log.Printf("solana rpc primary=%s fallback=%s",
		web3.RPCProviderHost(solanaRPC.URL("solana-mainnet")),
		web3.RPCProviderHost(web3.SolanaRPCFallbackURL("solana-mainnet")),
	)

	jobStore := jobs.NewStore(nil)
	jobQueue := jobs.Queue(jobs.NoopQueue{})
	if natsURL := os.Getenv("NATS_URL"); natsURL != "" {
		jobQueue = jobs.NewNATSQueue(natsURL, os.Getenv("NATS_SUBJECT_PREFIX"))
	}
	defer jobQueue.Close()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if handlers.ConfiguredNeonAuthJWKSURL() == "" {
		log.Printf("NEON_AUTH_JWKS_URL is not set")
	}
	staticDir := resolveStaticDir(os.Getenv("STATIC_DIR"))
	log.Printf("static public path: %s", staticDir)
	handler := englishPublicHTML(apihttp.NewServer(
		nil,
		dbInitError,
		os.Getenv("ADMIN_PASSWORD"),
		firstEnv("CORS_ORIGIN", "CORS_ALLOWED_ORIGIN"),
		staticDir,
		apihttp.WithReadDB(nil),
		apihttp.WithCache(appCache),
		apihttp.WithSolanaRPC(solanaRPC),
		apihttp.WithJobStore(jobStore),
		apihttp.WithJobQueue(jobQueue),
	))
	server := newHTTPServer(port, handler)

	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("api listening on %s", server.Addr)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http server failed: %v", err)
		}
	case <-appCtx.Done():
		log.Printf("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
			_ = server.Close()
		}
		select {
		case err := <-serverErrors:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("http server stopped with error: %v", err)
			}
		case <-shutdownCtx.Done():
			log.Printf("http server shutdown deadline reached")
		}
	}
}

func newHTTPServer(port string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              ":" + strings.TrimSpace(port),
		Handler:           handler,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
	}
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return ""
}

func resolveStaticDir(configured string) string {
	if configured != "" {
		return configured
	}
	for _, candidate := range []string{"public", filepath.Join("/app", "public"), filepath.Join("koschei", "api", "public")} {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	return filepath.Join("koschei", "api", "public")
}

func buildCache() cache.Cache {
	if os.Getenv("CACHE_ENABLED") == "false" {
		return cache.NewNoop()
	}
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		return cache.NewMemory()
	}
	redisCache, err := cache.NewRedis(redisURL, os.Getenv("REDIS_TLS") == "true")
	if err != nil {
		log.Printf("redis cache unavailable, using in-memory cache: %v", err)
		return cache.NewMemory()
	}
	return redisCache
}
