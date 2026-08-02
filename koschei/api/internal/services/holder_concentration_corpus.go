package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"math"
	"strings"
	"time"
)

const (
	HolderConcentrationStatsKey          = "owner_resolved_top_share_v1"
	HolderConcentrationBucketWidth       = 1.0
	HolderConcentrationMinimumSampleSize = int64(100)
	holderConcentrationCorpusInterval    = 12 * time.Hour
)

type HolderConcentrationContext struct {
	Available         bool      `json:"available"`
	Status            string    `json:"status"`
	StatsKey          string    `json:"stats_key"`
	TopSharePct       float64   `json:"top_share_pct"`
	TopPercentile     float64   `json:"top_percentile,omitempty"`
	SampleCount       int64     `json:"sample_count"`
	BucketWidth       float64   `json:"bucket_width"`
	CalculatedAt      time.Time `json:"calculated_at,omitempty"`
	SourceWindowStart time.Time `json:"source_window_start,omitempty"`
	SourceWindowEnd   time.Time `json:"source_window_end,omitempty"`
	Method            string    `json:"method"`
	Limitations       []string  `json:"limitations"`
}

func HolderConcentrationObservation(holder HolderIntelligence) (string, float64, bool) {
	if !holder.Available || !holder.OwnerAggregationApplied || holder.CirculatingSupply <= 0 {
		return "", 0, false
	}
	for _, row := range holder.Rows {
		wallet := strings.TrimSpace(row.OwnerWallet)
		if row.OwnerResolved && row.RiskBearing && !row.ExcludedFromHolderRisk && wallet != "" {
			share := holder.TopOwnerPercentage
			if share < 0 || share > 100 {
				return "", 0, false
			}
			return wallet, roundHolderCorpus(share), true
		}
	}
	return "", 0, false
}

func CaptureHolderConcentrationObservation(ctx context.Context, db *sql.DB, network, mint string, holder HolderIntelligence, observedAt time.Time) error {
	if db == nil {
		return nil
	}
	mint = strings.TrimSpace(mint)
	if mint == "" {
		return nil
	}
	wallet, share, ok := HolderConcentrationObservation(holder)
	if !ok {
		return nil
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO holder_concentration_observations
		(network,mint,owner_wallet,top_owner_share_pct,first_observed_at,last_observed_at,scan_count)
		VALUES ($1,$2,$3,$4,$5,$5,1)
		ON CONFLICT (network,mint) DO UPDATE SET
			owner_wallet=EXCLUDED.owner_wallet,
			top_owner_share_pct=EXCLUDED.top_owner_share_pct,
			last_observed_at=GREATEST(holder_concentration_observations.last_observed_at,EXCLUDED.last_observed_at),
			scan_count=holder_concentration_observations.scan_count+1`,
		normalizeRadarNetwork(network), mint, wallet, share, observedAt.UTC(),
	)
	return err
}

func BuildHolderConcentrationHistogram(shares []float64, bucketWidth float64) []int64 {
	if bucketWidth <= 0 || bucketWidth > 100 {
		bucketWidth = HolderConcentrationBucketWidth
	}
	bucketCount := int(math.Ceil(100/bucketWidth)) + 1
	counts := make([]int64, bucketCount)
	for _, share := range shares {
		if math.IsNaN(share) || math.IsInf(share, 0) || share < 0 || share > 100 {
			continue
		}
		index := int(math.Floor(share / bucketWidth))
		if index < 0 {
			index = 0
		}
		if index >= len(counts) {
			index = len(counts) - 1
		}
		counts[index]++
	}
	return counts
}

func HolderConcentrationTopPercentile(share, bucketWidth float64, counts []int64) (float64, int64, bool) {
	if bucketWidth <= 0 || len(counts) == 0 || share < 0 || share > 100 {
		return 0, 0, false
	}
	var sampleCount int64
	for _, count := range counts {
		if count > 0 {
			sampleCount += count
		}
	}
	if sampleCount == 0 {
		return 0, 0, false
	}
	index := int(math.Floor(share / bucketWidth))
	if index < 0 {
		index = 0
	}
	if index >= len(counts) {
		index = len(counts) - 1
	}
	var asOrMoreConcentrated int64
	for i := index; i < len(counts); i++ {
		if counts[i] > 0 {
			asOrMoreConcentrated += counts[i]
		}
	}
	percentile := float64(asOrMoreConcentrated) / float64(sampleCount) * 100
	return roundHolderCorpus(percentile), sampleCount, true
}

func RefreshHolderConcentrationCorpus(ctx context.Context, db *sql.DB, now time.Time) error {
	if db == nil {
		return nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT top_owner_share_pct::double precision,last_observed_at
		FROM holder_concentration_observations
		ORDER BY network,mint`)
	if err != nil {
		return err
	}
	defer rows.Close()
	shares := []float64{}
	var windowStart, windowEnd time.Time
	for rows.Next() {
		var share float64
		var observedAt time.Time
		if rows.Scan(&share, &observedAt) != nil {
			continue
		}
		if share < 0 || share > 100 {
			continue
		}
		shares = append(shares, share)
		observedAt = observedAt.UTC()
		if windowStart.IsZero() || observedAt.Before(windowStart) {
			windowStart = observedAt
		}
		if windowEnd.IsZero() || observedAt.After(windowEnd) {
			windowEnd = observedAt
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	counts := BuildHolderConcentrationHistogram(shares, HolderConcentrationBucketWidth)
	raw, err := json.Marshal(counts)
	if err != nil {
		return err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO holder_concentration_corpus_stats
		(stats_key,sample_count,bucket_width,bucket_counts,calculated_at,source_window_start,source_window_end)
		VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7)
		ON CONFLICT (stats_key) DO UPDATE SET
			sample_count=EXCLUDED.sample_count,
			bucket_width=EXCLUDED.bucket_width,
			bucket_counts=EXCLUDED.bucket_counts,
			calculated_at=EXCLUDED.calculated_at,
			source_window_start=EXCLUDED.source_window_start,
			source_window_end=EXCLUDED.source_window_end`,
		HolderConcentrationStatsKey, int64(len(shares)), HolderConcentrationBucketWidth, string(raw), now.UTC(), nullableCorpusTime(windowStart), nullableCorpusTime(windowEnd),
	)
	return err
}

func LoadHolderConcentrationContext(ctx context.Context, db *sql.DB, holder HolderIntelligence) HolderConcentrationContext {
	out := HolderConcentrationContext{
		Status: "corpus_unavailable", StatsKey: HolderConcentrationStatsKey,
		BucketWidth: HolderConcentrationBucketWidth,
		Method:      "distinct_mint_latest_owner_resolved_top_share_histogram",
		Limitations: []string{},
	}
	_, share, eligible := HolderConcentrationObservation(holder)
	if !eligible {
		out.Status = "owner_resolved_share_unavailable"
		out.Limitations = append(out.Limitations, "Percentile context requires the same owner-resolved, infrastructure-excluded concentration used by URD-C005.")
		return out
	}
	out.TopSharePct = share
	if db == nil {
		out.Limitations = append(out.Limitations, "Corpus database is unavailable.")
		return out
	}
	var raw []byte
	var windowStart, windowEnd sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT sample_count,bucket_width::double precision,bucket_counts,calculated_at,source_window_start,source_window_end
		FROM holder_concentration_corpus_stats
		WHERE stats_key=$1`, HolderConcentrationStatsKey).Scan(
		&out.SampleCount, &out.BucketWidth, &raw, &out.CalculatedAt, &windowStart, &windowEnd,
	)
	if err != nil {
		out.Limitations = append(out.Limitations, "Corpus statistics have not been calculated yet.")
		return out
	}
	if windowStart.Valid {
		out.SourceWindowStart = windowStart.Time.UTC()
	}
	if windowEnd.Valid {
		out.SourceWindowEnd = windowEnd.Time.UTC()
	}
	counts := []int64{}
	if json.Unmarshal(raw, &counts) != nil {
		out.Status = "corpus_decode_failed"
		out.Limitations = append(out.Limitations, "Corpus histogram could not be decoded.")
		return out
	}
	percentile, counted, ok := HolderConcentrationTopPercentile(share, out.BucketWidth, counts)
	if !ok || counted != out.SampleCount {
		out.Status = "corpus_inconsistent"
		out.Limitations = append(out.Limitations, "Corpus sample count and histogram totals do not match.")
		return out
	}
	if out.SampleCount < HolderConcentrationMinimumSampleSize {
		out.Status = "corpus_sample_too_small"
		out.Limitations = append(out.Limitations, "Percentile is withheld until at least 100 distinct owner-resolved token observations exist.")
		return out
	}
	out.Available = true
	out.Status = "observed_corpus_percentile"
	out.TopPercentile = percentile
	out.Limitations = append(out.Limitations, "Percentile is descriptive context from previously scanned distinct mints; it cannot change the deterministic verdict or prove intent.")
	return out
}

func StartHolderConcentrationCorpusWorker(ctx context.Context, db *sql.DB) func() {
	if db == nil {
		return func() {}
	}
	workerCtx, cancel := context.WithCancel(ctx)
	go func() {
		refresh := func() {
			stepCtx, stepCancel := context.WithTimeout(workerCtx, 2*time.Minute)
			defer stepCancel()
			if err := RefreshHolderConcentrationCorpus(stepCtx, db, time.Now().UTC()); err != nil && stepCtx.Err() == nil {
				log.Printf("holder concentration corpus refresh error: %v", err)
			}
		}
		refresh()
		ticker := time.NewTicker(holderConcentrationCorpusInterval)
		defer ticker.Stop()
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()
	return cancel
}

func nullableCorpusTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func roundHolderCorpus(value float64) float64 {
	return math.Round(value*10000) / 10000
}
