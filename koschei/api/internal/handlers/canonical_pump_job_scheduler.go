package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/jobs"
	"koschei/api/internal/services"
)

type canonicalPumpJobScheduler struct {
	RadarStore      *services.SecurityRadarStore
	JobStore        *jobs.Store
	Provider        services.PumpVolumeProvider
	ThresholdUSD    float64
	PollEvery       time.Duration
	CandidateLimit  int
	MaxJobsPerCycle int
	ReportCooldown  time.Duration
	AttemptCooldown time.Duration
}

func StartCanonicalPumpJobScheduler(ctx context.Context, db *sql.DB, store *jobs.Store) func() {
	if !CanonicalInvestigationJobWorkerEnabled() || !services.AutomaticBackgroundScanningEnabled() || !services.PumpHighVolumeRadarEnabled() || db == nil {
		return func() {}
	}
	if store == nil {
		store = jobs.NewStore(db)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	scheduler := &canonicalPumpJobScheduler{
		RadarStore: services.NewSecurityRadarStore(db), JobStore: store,
		Provider:        services.NewDexScreenerPumpVolumeClient(),
		ThresholdUSD:    services.PumpHighVolumeThresholdUSD(),
		PollEvery:       services.PumpHighVolumePollInterval(),
		CandidateLimit:  canonicalPumpEnvInt("PUMP_HIGH_VOLUME_CANDIDATE_PAGE_SIZE", 900, 30, 3000),
		MaxJobsPerCycle: canonicalPumpMaxJobsPerCycle(),
		ReportCooldown:  time.Duration(canonicalPumpEnvInt("PUMP_HIGH_VOLUME_REPORT_COOLDOWN_SECONDS", 21600, 900, 86400)) * time.Second,
		AttemptCooldown: time.Duration(canonicalPumpEnvInt("PUMP_HIGH_VOLUME_ATTEMPT_COOLDOWN_SECONDS", 1800, 300, 21600)) * time.Second,
	}
	go scheduler.Start(workerCtx)
	log.Printf("canonical pump job scheduler started volume_window=24h threshold=%.0f poll=%s max_jobs_per_cycle=%d", scheduler.ThresholdUSD, scheduler.PollEvery, scheduler.MaxJobsPerCycle)
	return cancel
}

func (s *canonicalPumpJobScheduler) Start(ctx context.Context) {
	if s == nil || s.RadarStore == nil || s.JobStore == nil || s.Provider == nil {
		return
	}
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if _, _, _, err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
				log.Printf("canonical pump job scheduler cycle failed: %v", err)
			}
			timer.Reset(s.PollEvery)
		}
	}
}

func (s *canonicalPumpJobScheduler) RunOnce(ctx context.Context) (candidateCount, qualifiedCount, queuedCount int, err error) {
	candidates, err := s.RadarStore.ListPumpPortalCandidates(ctx, s.CandidateLimit, time.Time{}, "")
	if err != nil {
		return 0, 0, 0, err
	}
	candidateCount = len(candidates)
	if len(candidates) == 0 {
		return candidateCount, 0, 0, nil
	}
	candidateByMint := map[string]services.PumpRadarCandidate{}
	mints := []string{}
	for _, candidate := range candidates {
		mint := strings.TrimSpace(candidate.Mint)
		if mint == "" || candidateByMint[mint].Mint != "" {
			continue
		}
		candidateByMint[mint] = candidate
		mints = append(mints, mint)
	}
	markets := map[string]services.PumpTokenMarket{}
	for start := 0; start < len(mints); start += 30 {
		end := start + 30
		if end > len(mints) {
			end = len(mints)
		}
		batch, fetchErr := s.Provider.Fetch24hVolumes(ctx, mints[start:end])
		if fetchErr != nil {
			return candidateCount, qualifiedCount, queuedCount, fetchErr
		}
		for mint, market := range batch {
			markets[mint] = market
		}
	}
	type qualified struct {
		Candidate services.PumpRadarCandidate
		Market    services.PumpTokenMarket
	}
	qualifiedRows := []qualified{}
	for mint, candidate := range candidateByMint {
		market, ok := markets[mint]
		if !ok || market.Volume24hUSD < s.ThresholdUSD {
			continue
		}
		qualifiedRows = append(qualifiedRows, qualified{Candidate: candidate, Market: market})
	}
	qualifiedCount = len(qualifiedRows)
	sort.SliceStable(qualifiedRows, func(i, j int) bool {
		if qualifiedRows[i].Market.Volume24hUSD != qualifiedRows[j].Market.Volume24hUSD {
			return qualifiedRows[i].Market.Volume24hUSD > qualifiedRows[j].Market.Volume24hUSD
		}
		return qualifiedRows[i].Candidate.ObservedAt.After(qualifiedRows[j].Candidate.ObservedAt)
	})

	for _, row := range qualifiedRows {
		if s.MaxJobsPerCycle > 0 && queuedCount >= s.MaxJobsPerCycle {
			break
		}
		reported, reportErr := s.RadarStore.PumpHighVolumeReportedRecently(ctx, row.Candidate.Mint, s.ReportCooldown)
		if reportErr != nil {
			return candidateCount, qualifiedCount, queuedCount, reportErr
		}
		if reported {
			continue
		}
		attempted, attemptErr := s.RadarStore.PumpHighVolumeAttemptedRecently(ctx, row.Candidate.Mint, s.AttemptCooldown)
		if attemptErr != nil {
			return candidateCount, qualifiedCount, queuedCount, attemptErr
		}
		if attempted {
			continue
		}
		eventID, eventErr := s.RadarStore.RecordPumpHighVolumeObservation(ctx, row.Candidate, row.Market, s.ThresholdUSD)
		if eventErr != nil {
			return candidateCount, qualifiedCount, queuedCount, eventErr
		}
		bucket := row.Market.ObservedAt.UTC().Truncate(s.ReportCooldown)
		if bucket.IsZero() {
			bucket = time.Now().UTC().Truncate(s.ReportCooldown)
		}
		dedupe := strings.Join([]string{"pump_volume_gate", row.Candidate.Mint, bucket.Format(time.RFC3339)}, "|")
		payload := canonicalInvestigationJobPayload{
			Mint: row.Candidate.Mint, Network: "solana-mainnet",
			Mode: "background_pump_high_volume", RootTarget: row.Candidate.Mint,
			Source: "pump_volume_gate", SourceEventID: eventID, Depth: 0,
			MaxDepth: canonicalWorkerEnvInt("ACTOR_RECURSIVE_MAX_DEPTH", 1, 1, 3), DedupeKey: dedupe,
		}
		_, created, createErr := s.JobStore.CreateUniqueActive(ctx, jobs.CreateInput{
			Type: CanonicalInvestigationJobType, Network: "solana-mainnet",
			Target: row.Candidate.Mint, Request: payload,
		}, dedupe)
		if createErr != nil {
			return candidateCount, qualifiedCount, queuedCount, createErr
		}
		if eventID != "" {
			_ = s.RadarStore.MarkPumpHighVolumeAttempted(ctx, eventID)
		}
		if created {
			queuedCount++
		}
	}
	log.Printf("canonical pump volume cycle: candidates=%d qualified=%d queued=%d threshold_usd=%.0f", candidateCount, qualifiedCount, queuedCount, s.ThresholdUSD)
	return candidateCount, qualifiedCount, queuedCount, nil
}

func canonicalPumpMaxJobsPerCycle() int {
	if services.OwnerUnlimitedAutomaticScanningEnabled() {
		return 0
	}
	return canonicalPumpEnvInt("PUMP_HIGH_VOLUME_MAX_REPORTS_PER_CYCLE", 1, 1, 20)
}

func canonicalPumpEnvInt(name string, fallback, minValue, maxValue int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil {
		return fallback
	}
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func canonicalPumpJobDedupeKey(mint string, observedAt time.Time, cooldown time.Duration) string {
	if cooldown <= 0 {
		cooldown = 6 * time.Hour
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	return fmt.Sprintf("pump_volume_gate|%s|%s", strings.TrimSpace(mint), observedAt.UTC().Truncate(cooldown).Format(time.RFC3339))
}
