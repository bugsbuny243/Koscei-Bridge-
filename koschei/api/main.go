package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"koschei/api/internal/alerts"
	"koschei/api/internal/cache"
	"koschei/api/internal/db"
	"koschei/api/internal/handlers"
	apihttp "koschei/api/internal/http"
	"koschei/api/internal/jobs"
	"koschei/api/internal/services"
	"koschei/api/internal/web3"
	"koschei/api/internal/webhooks"
)

func main() {
	log.Printf("koschei api starting")
	log.Printf("migrations path: /app/migrations")
	if missing := services.MissingProductionSecurityEnv(); len(missing) > 0 {
		log.Fatalf("CRITICAL: missing required production security env vars: %s", strings.Join(missing, ", "))
	}

	databaseURL := os.Getenv("DATABASE_URL")
	var conn *sql.DB
	var readConn *sql.DB
	var dbInitError string

	if databaseURL == "" {
		dbInitError = "DATABASE_URL is not set"
		log.Printf("database unavailable: %s", dbInitError)
	} else {
		var err error
		conn, err = db.Connect(databaseURL)
		if err != nil {
			dbInitError = err.Error()
			log.Printf("database unavailable: %v", err)
		} else {
			log.Printf("database connected")
		}
	}
	if conn != nil {
		defer conn.Close()
	}
	readURL := os.Getenv("DATABASE_READ_URL")
	if readURL != "" && readURL != databaseURL {
		var err error
		readConn, err = db.ConnectReplica(readURL)
		if err != nil {
			log.Printf("database read replica unavailable, falling back to primary: %v", err)
			readConn = conn
		} else {
			defer readConn.Close()
			log.Printf("database read replica connected")
		}
	} else {
		readConn = conn
	}

	appCache := buildCache()
	defer appCache.Close()
	solanaRPC := web3.NewSolanaRPC(appCache)
	log.Printf("solana rpc primary=%s fallback=%s",
		web3.RPCProviderHost(solanaRPC.URL("solana-mainnet")),
		web3.RPCProviderHost(web3.SolanaRPCFallbackURL("solana-mainnet")),
	)
	appCtx := context.Background()

	// Retention remains active because it performs database hygiene only. Every
	// quota-consuming automatic scanner is opt-in through the master switch.
	stopSecurityRadars := services.StartSecurityRadarWatcher(appCtx, conn, solanaRPC)
	defer stopSecurityRadars()
	if services.AutomaticBackgroundScanningEnabled() {
		stopPumpPortal := services.StartPumpPortalRadarIfEnabled(appCtx, conn)
		defer stopPumpPortal()
		stopActorDefense := services.StartActorDefenseCorrelator(appCtx, conn)
		defer stopActorDefense()
		if services.SolanaRPCLimitSaverEnabled() && !services.ForceBackgroundRadarEnabled() {
			log.Printf("broad Solana streams paused: RPC saver protects quota; explicitly enabled selective workers may remain active")
		} else {
			stopSBX1Stream := services.StartSecurityRadarStreamIfEnabled(appCtx, conn)
			defer stopSBX1Stream()
		}
		stopWatchlistMonitor := handlers.StartWatchlistMonitor(appCtx, conn)
		defer stopWatchlistMonitor()
	} else {
		log.Printf("automatic scanning disabled: no Pump discovery, radar polling, background stream, actor correlation or watchlist refresh; manual scans and Safe Check remain available")
	}

	jobStore := jobs.NewStore(conn)
	jobQueue := jobs.Queue(jobs.NoopQueue{})
	if natsURL := os.Getenv("NATS_URL"); natsURL != "" {
		jobQueue = jobs.NewNATSQueue(natsURL, os.Getenv("NATS_SUBJECT_PREFIX"))
	}
	defer jobQueue.Close()

	// Empty database-backed queues previously polled Neon every 2-4 seconds and
	// prevented scale-to-zero even with zero traffic. Production now fails closed
	// to cost-safe manual/API operation unless polling workers are explicitly
	// enabled. Deploy polling consumers as a dedicated worker service and set
	// KOSCHEI_DATABASE_POLLING_WORKERS_ENABLED=true there.
	pollingDefault := !strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production")
	if envBoolDefault("KOSCHEI_DATABASE_POLLING_WORKERS_ENABLED", pollingDefault) {
		stopWebhookDeliveries := webhooks.StartDeliveryWorker(appCtx, conn)
		defer stopWebhookDeliveries()
		stopSecurityAlertDeliveries := alerts.StartDeliveryWorker(appCtx, conn)
		defer stopSecurityAlertDeliveries()

		// Existing web3_jobs rows now have a real consumer. Deep canonical scans
		// are detached from HTTP request lifetime and processed sequentially.
		stopCanonicalWorker := handlers.StartCanonicalInvestigationJobWorker(appCtx, conn, readConn, solanaRPC, jobStore)
		defer stopCanonicalWorker()
		stopCanonicalPumpScheduler := handlers.StartCanonicalPumpJobScheduler(appCtx, conn, jobStore)
		defer stopCanonicalPumpScheduler()
	} else {
		log.Printf("database polling workers disabled: Neon cost guard active; manual scans, synchronous API routes and public SOC remain available")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if handlers.ConfiguredNeonAuthJWKSURL() == "" {
		log.Printf("NEON_AUTH_JWKS_URL is not set")
	}
	staticDir := resolveStaticDir(os.Getenv("STATIC_DIR"))
	log.Printf("static public path: %s", staticDir)
	srv := apihttp.NewServer(conn, dbInitError, os.Getenv("ADMIN_PASSWORD"), firstEnv("CORS_ORIGIN", "CORS_ALLOWED_ORIGIN"), staticDir, apihttp.WithReadDB(readConn), apihttp.WithCache(appCache), apihttp.WithSolanaRPC(solanaRPC), apihttp.WithJobStore(jobStore), apihttp.WithJobQueue(jobQueue))
	log.Printf("api listening on :%s", port)
	if err := http.ListenAndServe(":"+port, srv); err != nil {
		log.Fatal(err)
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

func envBoolDefault(name string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
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
