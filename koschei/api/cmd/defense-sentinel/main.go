package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"koschei/api/internal/cache"
	"koschei/api/internal/db"
	"koschei/api/internal/defense"
	"koschei/api/internal/web3"
)

func main() {
	log.Printf("koschei defense sentinel starting")
	if !envBool("KOSCHEI_DEFENSE_SENTINEL_ENABLED", false) {
		log.Fatal("KOSCHEI_DEFENSE_SENTINEL_ENABLED is false")
	}
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	conn, err := db.ConnectReplica(databaseURL)
	if err != nil {
		log.Fatalf("defense sentinel database connection failed: %v", err)
	}
	defer conn.Close()

	sentinelID := strings.TrimSpace(os.Getenv("KOSCHEI_DEFENSE_SENTINEL_ID"))
	if sentinelID == "" {
		host, _ := os.Hostname()
		if strings.TrimSpace(host) == "" {
			host = "railway-sentinel"
		}
		sentinelID = "sentinel-" + host
	}
	pollInterval := envDurationSeconds("KOSCHEI_DEFENSE_SENTINEL_POLL_SECONDS", 10, 2, 300)
	checkTimeout := envDurationSeconds("KOSCHEI_DEFENSE_SENTINEL_CHECK_TIMEOUT_SECONDS", 45, 10, 180)
	lease := checkTimeout + 30*time.Second
	rpc := web3.NewSolanaRPC(cache.NewNoop())
	log.Printf("defense sentinel ready id=%s poll=%s check_timeout=%s", sentinelID, pollInterval, checkTimeout)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("defense sentinel stopped")
			return
		default:
		}
		claimCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		monitor, ok, claimErr := defense.ClaimDueProgramMonitor(claimCtx, conn, sentinelID, lease)
		cancel()
		if claimErr != nil {
			log.Printf("defense sentinel claim error: %v", claimErr)
			sleepContext(ctx, pollInterval)
			continue
		}
		if !ok {
			sleepContext(ctx, pollInterval)
			continue
		}
		log.Printf("defense sentinel checking monitor=%s program=%s", monitor.MonitorRef, monitor.ProgramID)
		checkCtx, checkCancel := context.WithTimeout(ctx, checkTimeout)
		result, checkErr := defense.CheckProgramMonitor(checkCtx, conn, rpc, monitor)
		checkCancel()
		if checkErr != nil {
			if err := defense.FailProgramMonitorCheck(context.Background(), conn, monitor, sentinelID, checkErr); err != nil {
				log.Printf("defense sentinel failure persistence error monitor=%s: %v", monitor.MonitorRef, err)
			}
			log.Printf("defense sentinel check failed monitor=%s: %v", monitor.MonitorRef, checkErr)
			continue
		}
		if result.BaselineCreated {
			log.Printf("defense sentinel baseline created monitor=%s snapshot=%s", monitor.MonitorRef, result.Current.SnapshotRef)
		} else if result.Event != nil {
			log.Printf("defense sentinel change observed monitor=%s event=%s severity=%s types=%s", monitor.MonitorRef, result.Event.EventRef, result.Event.Severity, strings.Join(result.Event.ChangeTypes, ","))
		} else {
			log.Printf("defense sentinel unchanged monitor=%s snapshot=%s", monitor.MonitorRef, result.Current.SnapshotRef)
		}
	}
}

func envBool(name string, fallback bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func envDurationSeconds(name string, fallback, minimum, maximum int) time.Duration {
	value := fallback
	if raw := strings.TrimSpace(os.Getenv(name)); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			value = parsed
		}
	}
	if value < minimum {
		value = minimum
	}
	if value > maximum {
		value = maximum
	}
	return time.Duration(value) * time.Second
}

func sleepContext(ctx context.Context, duration time.Duration) {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
