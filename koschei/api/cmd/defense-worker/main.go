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

	"koschei/api/internal/db"
	"koschei/api/internal/defense"
)

func main() {
	log.Printf("koschei defense worker starting")
	workerEnabled := envBool("KOSCHEI_DEFENSE_WORKER_ENABLED", false)
	sandboxEnabled := envBool("KOSCHEI_DEFENSE_SANDBOX_ENABLED", false)
	if !workerEnabled {
		log.Fatal("KOSCHEI_DEFENSE_WORKER_ENABLED is false")
	}
	if !sandboxEnabled {
		log.Fatal("KOSCHEI_DEFENSE_SANDBOX_ENABLED must be true on the isolated worker")
	}
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	conn, err := db.ConnectReplica(databaseURL)
	if err != nil {
		log.Fatalf("defense worker database connection failed: %v", err)
	}
	defer conn.Close()

	workerID := strings.TrimSpace(os.Getenv("KOSCHEI_DEFENSE_WORKER_ID"))
	if workerID == "" {
		host, _ := os.Hostname()
		if strings.TrimSpace(host) == "" {
			host = "railway-worker"
		}
		workerID = "defense-" + host
	}
	workerImageDigest := strings.TrimSpace(os.Getenv("KOSCHEI_DEFENSE_WORKER_IMAGE_DIGEST"))
	runtime := defense.LiteSVMWorkerRuntime{
		WorkerID:                workerID,
		WorkerImageDigest:       workerImageDigest,
		WorkRoot:                strings.TrimSpace(os.Getenv("KOSCHEI_DEFENSE_WORK_ROOT")),
		WorkerEnabled:           workerEnabled,
		SandboxEnabled:          sandboxEnabled,
		HarnessExecutionEnabled: envBool("KOSCHEI_DEFENSE_HARNESS_EXECUTION_ENABLED", false),
		LiteSVMExecutionEnabled: envBool("KOSCHEI_DEFENSE_LITESVM_EXECUTION_ENABLED", false),
		NetworkIsolated:         envBool("KOSCHEI_DEFENSE_NETWORK_ISOLATED", false),
	}
	phase12CEnabled := runtime.HarnessExecutionEnabled || runtime.LiteSVMExecutionEnabled
	if phase12CEnabled {
		if !runtime.HarnessExecutionEnabled || !runtime.LiteSVMExecutionEnabled {
			log.Fatal("both Phase 12C execution gates must be true together")
		}
		if !runtime.NetworkIsolated {
			log.Fatal("KOSCHEI_DEFENSE_NETWORK_ISOLATED must be true before Phase 12C execution")
		}
		if workerImageDigest == "" {
			log.Fatal("KOSCHEI_DEFENSE_WORKER_IMAGE_DIGEST is required before Phase 12C execution")
		}
		if runtime.WorkRoot == "" {
			log.Fatal("KOSCHEI_DEFENSE_WORK_ROOT is required before Phase 12C execution")
		}
	}

	attestCtx, attestCancel := context.WithTimeout(context.Background(), 30*time.Second)
	attestations, attestErr := defense.AttestPinnedLocalToolchain(attestCtx, conn, workerID)
	attestCancel()
	if attestErr != nil {
		if phase12CEnabled {
			log.Fatalf("defense worker toolchain attestation failed while Phase 12C is enabled: %v", attestErr)
		}
		log.Printf("defense worker toolchain attestation failed: %v", attestErr)
	} else {
		for _, item := range attestations {
			log.Printf("defense worker toolchain tool=%s available=%t pinned=%t version=%q image=%q", item.ToolName, item.Available, item.Pinned, item.VersionOutput, item.WorkerImageDigest)
		}
	}

	if phase12CEnabled {
		dependencyCtx, dependencyCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		dependencyEvidence, dependencyErr := defense.AttestOfflineDependencyRuntimeStore(dependencyCtx, conn, workerID, workerImageDigest)
		dependencyCancel()
		if dependencyErr != nil {
			log.Fatalf("defense worker offline dependency attestation failed: %v", dependencyErr)
		}
		log.Printf("defense worker offline dependencies verified ref=%s inventory=%s vendor=%s files=%d bytes=%d image=%s",
			dependencyEvidence.InventoryRef, dependencyEvidence.InventoryHash, dependencyEvidence.VendorTreeHash,
			dependencyEvidence.FileCount, dependencyEvidence.TotalBytes, dependencyEvidence.WorkerImageDigest)
	}

	pollInterval := envDurationSeconds("KOSCHEI_DEFENSE_WORKER_POLL_SECONDS", 2, 1, 60)
	jobTimeout := envDurationSeconds("KOSCHEI_DEFENSE_WORKER_JOB_TIMEOUT_SECONDS", 900, 30, 3600)
	lease := jobTimeout + 60*time.Second
	log.Printf("defense worker ready id=%s poll=%s job_timeout=%s litesvm_enabled=%t network_isolated=%t", workerID, pollInterval, jobTimeout, runtime.LiteSVMExecutionEnabled, runtime.NetworkIsolated)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("defense worker stopped")
			return
		default:
		}
		claimCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		job, ok, claimErr := defense.ClaimWorkerJob(claimCtx, conn, workerID, lease)
		cancel()
		if claimErr != nil {
			log.Printf("defense worker claim error: %v", claimErr)
			sleepContext(ctx, pollInterval)
			continue
		}
		if !ok {
			sleepContext(ctx, pollInterval)
			continue
		}
		log.Printf("defense worker claimed job=%s action=%s attempt=%d/%d", job.JobRef, job.Action, job.Attempts, job.MaxAttempts)
		jobCtx, jobCancel := context.WithTimeout(ctx, jobTimeout)
		result, processErr := defense.ProcessWorkerJobWithRuntime(jobCtx, conn, job, runtime)
		jobCancel()
		if processErr != nil {
			if err := defense.FailWorkerJob(context.Background(), conn, job, workerID, "worker_execution_failed", processErr.Error()); err != nil {
				log.Printf("defense worker fail persistence error job=%s: %v", job.JobRef, err)
			}
			log.Printf("defense worker failed job=%s: %v", job.JobRef, processErr)
			continue
		}
		if err := defense.CompleteWorkerJob(context.Background(), conn, job, workerID, result); err != nil {
			log.Printf("defense worker completion persistence error job=%s: %v", job.JobRef, err)
			continue
		}
		log.Printf("defense worker completed job=%s", job.JobRef)
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
