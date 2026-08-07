package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const fundingClusterStoreTimeout = 1500 * time.Millisecond

type securityRadarStoreContextKey struct{}

// WithSecurityRadarStore attaches an already-owned store to one scan request.
// It does not open a pool, LISTEN connection or background worker, so Neon can
// still scale to zero when the request finishes.
func WithSecurityRadarStore(ctx context.Context, store *SecurityRadarStore) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if store == nil || store.DB == nil {
		return ctx
	}
	return context.WithValue(ctx, securityRadarStoreContextKey{}, store)
}

func securityRadarStoreFromContext(ctx context.Context) *SecurityRadarStore {
	if ctx == nil {
		return nil
	}
	store, _ := ctx.Value(securityRadarStoreContextKey{}).(*SecurityRadarStore)
	if store == nil || store.DB == nil {
		return nil
	}
	return store
}

type fundingClusterObservation struct {
	FundingSource             string
	ClusterKind               string
	MemberCount               int
	MemberWallets             []string
	HolderPercentage          *float64
	SynchronizationSlotSpread *int64
}

// FundingSourceRecurrence is a read-back projection for one shared funding
// wallet observed on the current target. OtherTargets contains only different
// token mints, never the current target repeated as evidence.
type FundingSourceRecurrence struct {
	FundingSource       string    `json:"funding_source"`
	DistinctTargets     int       `json:"distinct_targets"`
	OtherTargets        []string  `json:"other_targets"`
	MemberWallets       []string  `json:"member_wallets"`
	FirstObservedAt     time.Time `json:"first_observed_at,omitempty"`
	LastObservedAt      time.Time `json:"last_observed_at,omitempty"`
	ReferencesComplete bool      `json:"references_complete"`
	StoredRowsVerified bool      `json:"stored_rows_verified"`
}

// FundingRecurrenceAnalysis keeps corpus read states explicit. An unavailable
// read is not rewritten as a negative finding and a reference gap cannot become
// evidence merely because the rollup count is non-zero.
type FundingRecurrenceAnalysis struct {
	Available      bool                      `json:"available"`
	Status         string                    `json:"status"`
	EvidenceStatus string                    `json:"evidence_status"`
	CurrentTarget  string                    `json:"current_target"`
	Network        string                    `json:"network"`
	Sources        []FundingSourceRecurrence `json:"sources"`
	Limitations    []string                  `json:"limitations"`
}

// CaptureFundingClusters persists only groups produced by holder-cluster
// analysis with at least two real member-wallet references. The actor rollup is
// recomputed from source rows inside the same transaction.
func (s *SecurityRadarStore) CaptureFundingClusters(ctx context.Context, target, network string, analysis HolderClusterAnalysis) error {
	if s == nil || s.DB == nil {
		return nil
	}
	target = strings.TrimSpace(target)
	network = normalizeRadarNetwork(network)
	if target == "" {
		return nil
	}
	observations := fundingClusterObservations(analysis)
	if len(observations) == 0 {
		return nil
	}

	storeCtx, cancel := context.WithTimeout(ctx, fundingClusterStoreTimeout)
	defer cancel()
	tx, err := s.DB.BeginTx(storeCtx, nil)
	if err != nil {
		return fmt.Errorf("begin funding cluster persistence: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	observedAt := time.Now().UTC()
	affected := map[string]bool{}
	for _, observation := range observations {
		memberWallets, err := json.Marshal(observation.MemberWallets)
		if err != nil {
			return fmt.Errorf("encode funding cluster wallets: %w", err)
		}
		_, err = tx.ExecContext(storeCtx, `
			INSERT INTO security_funding_clusters (
				funding_source,cluster_kind,target,network,member_count,member_wallets,
				holder_percentage,synchronization_slot_spread,first_observed_at,last_observed_at,observation_count
			) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$9,1)
			ON CONFLICT (funding_source,cluster_kind,target,network) DO UPDATE SET
				member_count=EXCLUDED.member_count,
				member_wallets=EXCLUDED.member_wallets,
				holder_percentage=EXCLUDED.holder_percentage,
				synchronization_slot_spread=EXCLUDED.synchronization_slot_spread,
				first_observed_at=LEAST(security_funding_clusters.first_observed_at,EXCLUDED.first_observed_at),
				last_observed_at=GREATEST(security_funding_clusters.last_observed_at,EXCLUDED.last_observed_at),
				observation_count=security_funding_clusters.observation_count+1`,
			observation.FundingSource, observation.ClusterKind, target, network,
			observation.MemberCount, string(memberWallets), observation.HolderPercentage,
			observation.SynchronizationSlotSpread, observedAt,
		)
		if err != nil {
			return fmt.Errorf("upsert funding cluster: %w", err)
		}
		affected[observation.FundingSource] = true
	}

	for fundingSource := range affected {
		_, err = tx.ExecContext(storeCtx, `
			INSERT INTO security_funding_cluster_actors (
				funding_source,network,distinct_targets,total_member_wallets,max_member_count,
				first_observed_at,last_observed_at
			)
			SELECT
				$1,$2,
				count(DISTINCT c.target)::integer,
				(
					SELECT count(DISTINCT wallet)::integer
					FROM security_funding_clusters c2
					CROSS JOIN LATERAL jsonb_array_elements_text(c2.member_wallets) AS wallet
					WHERE c2.funding_source=$1 AND c2.network=$2
				),
				max(c.member_count)::integer,
				min(c.first_observed_at),
				max(c.last_observed_at)
			FROM security_funding_clusters c
			WHERE c.funding_source=$1 AND c.network=$2
			GROUP BY c.funding_source,c.network
			ON CONFLICT (funding_source,network) DO UPDATE SET
				distinct_targets=EXCLUDED.distinct_targets,
				total_member_wallets=EXCLUDED.total_member_wallets,
				max_member_count=EXCLUDED.max_member_count,
				first_observed_at=EXCLUDED.first_observed_at,
				last_observed_at=EXCLUDED.last_observed_at`, fundingSource, network)
		if err != nil {
			return fmt.Errorf("recompute funding actor rollup: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit funding cluster persistence: %w", err)
	}
	return nil
}

// LoadFundingRecurrence reads the actor rollup and its source rows for funding
// wallets observed on the current target. Same-amount keys remain in the corpus
// but are intentionally excluded from the cross-token funder-wallet rule.
func (s *SecurityRadarStore) LoadFundingRecurrence(ctx context.Context, target, network string, analysis HolderClusterAnalysis) (FundingRecurrenceAnalysis, error) {
	target = strings.TrimSpace(target)
	network = normalizeRadarNetwork(network)
	out := FundingRecurrenceAnalysis{
		Status: "not_investigated", EvidenceStatus: "not_investigated",
		CurrentTarget: target, Network: network, Sources: []FundingSourceRecurrence{}, Limitations: []string{},
	}
	if s == nil || s.DB == nil || target == "" {
		out.Status = "unavailable"
		out.EvidenceStatus = "unavailable"
		out.Limitations = append(out.Limitations, "Funding corpus database or current target is unavailable.")
		return out, nil
	}
	funders := currentSharedFunders(analysis)
	if len(funders) == 0 {
		out.Available = true
		out.Status = "not_applicable"
		out.EvidenceStatus = "not_applicable"
		return out, nil
	}

	readCtx, cancel := context.WithTimeout(ctx, fundingClusterStoreTimeout)
	defer cancel()
	out.Available = true
	out.Status = "observed_no_recurrence"
	out.EvidenceStatus = "observed"

	for _, fundingSource := range funders {
		var distinctTargets int
		err := s.DB.QueryRowContext(readCtx, `
			SELECT distinct_targets
			FROM security_funding_cluster_actors
			WHERE funding_source=$1 AND network=$2`, fundingSource, network).Scan(&distinctTargets)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			out.Available = false
			out.Status = "unavailable"
			out.EvidenceStatus = "unavailable"
			out.Limitations = append(out.Limitations, "Funding actor rollup query failed.")
			return out, err
		}

		rows, err := s.DB.QueryContext(readCtx, `
			SELECT target,member_wallets,first_observed_at,last_observed_at
			FROM security_funding_clusters
			WHERE funding_source=$1 AND network=$2 AND cluster_kind='shared_funder'
			ORDER BY target`, fundingSource, network)
		if err != nil {
			out.Available = false
			out.Status = "unavailable"
			out.EvidenceStatus = "unavailable"
			out.Limitations = append(out.Limitations, "Funding source-row query failed.")
			return out, err
		}

		item := FundingSourceRecurrence{FundingSource: fundingSource, DistinctTargets: distinctTargets, OtherTargets: []string{}, MemberWallets: []string{}, StoredRowsVerified: true}
		rowCount := 0
		for rows.Next() {
			var rowTarget string
			var memberRaw []byte
			var firstObservedAt, lastObservedAt time.Time
			if err := rows.Scan(&rowTarget, &memberRaw, &firstObservedAt, &lastObservedAt); err != nil {
				_ = rows.Close()
				return out, err
			}
			rowCount++
			memberWallets := []string{}
			if json.Unmarshal(memberRaw, &memberWallets) != nil {
				item.StoredRowsVerified = false
			}
			memberWallets = uniqueFundingStrings(memberWallets)
			if len(memberWallets) < 2 || firstObservedAt.IsZero() || lastObservedAt.IsZero() {
				item.StoredRowsVerified = false
			}
			item.MemberWallets = append(item.MemberWallets, memberWallets...)
			if item.FirstObservedAt.IsZero() || firstObservedAt.Before(item.FirstObservedAt) {
				item.FirstObservedAt = firstObservedAt.UTC()
			}
			if item.LastObservedAt.IsZero() || lastObservedAt.After(item.LastObservedAt) {
				item.LastObservedAt = lastObservedAt.UTC()
			}
			rowTarget = strings.TrimSpace(rowTarget)
			if rowTarget != "" && rowTarget != target {
				item.OtherTargets = append(item.OtherTargets, rowTarget)
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return out, err
		}
		_ = rows.Close()
		item.MemberWallets = uniqueFundingStrings(item.MemberWallets)
		item.OtherTargets = uniqueFundingStrings(item.OtherTargets)
		if rowCount == 0 {
			item.StoredRowsVerified = false
		}
		item.ReferencesComplete = strings.TrimSpace(item.FundingSource) != "" && len(item.OtherTargets) > 0
		out.Sources = append(out.Sources, item)
	}

	hasRecurrence := false
	allVerified := true
	referenceGap := false
	for _, item := range out.Sources {
		if item.DistinctTargets < 2 {
			continue
		}
		if !item.ReferencesComplete {
			referenceGap = true
			continue
		}
		hasRecurrence = true
		if !item.StoredRowsVerified {
			allVerified = false
		}
	}
	switch {
	case hasRecurrence && allVerified:
		out.Status = "verified_recurrence"
		out.EvidenceStatus = "verified"
	case hasRecurrence:
		out.Status = "observed_recurrence"
		out.EvidenceStatus = "observed"
	case referenceGap:
		out.Status = "reference_gap"
		out.EvidenceStatus = "unavailable"
		out.Limitations = append(out.Limitations, "Cross-token count exists but funder-plus-other-target references are incomplete; recurrence is withheld.")
	}
	return out, nil
}

func fundingClusterObservations(analysis HolderClusterAnalysis) []fundingClusterObservation {
	out := []fundingClusterObservation{}
	appendGroups := func(kind string, groups []HolderClusterGroup) {
		for _, group := range groups {
			fundingSource := strings.TrimSpace(group.Key)
			wallets := uniqueFundingStrings(group.Wallets)
			if fundingSource == "" || group.MemberCount < 2 || len(wallets) < 2 || len(wallets) < group.MemberCount {
				continue
			}
			observation := fundingClusterObservation{
				FundingSource: fundingSource, ClusterKind: kind, MemberCount: group.MemberCount,
				MemberWallets: wallets, HolderPercentage: finiteFundingPercentage(group.HolderPercentage),
				SynchronizationSlotSpread: fundingGroupSlotSpread(wallets, analysis.Wallets),
			}
			out = append(out, observation)
		}
	}
	appendGroups("shared_funder", analysis.SharedFundingGroups)
	appendGroups("same_amount", analysis.SameAmountGroups)
	return out
}

func currentSharedFunders(analysis HolderClusterAnalysis) []string {
	values := []string{}
	for _, group := range analysis.SharedFundingGroups {
		if group.MemberCount >= 2 && len(uniqueFundingStrings(group.Wallets)) >= 2 {
			values = append(values, group.Key)
		}
	}
	return uniqueFundingStrings(values)
}

func finiteFundingPercentage(value float64) *float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 100 {
		return nil
	}
	copy := value
	return &copy
}

func fundingGroupSlotSpread(wallets []string, observations []HolderClusterWallet) *int64 {
	wanted := map[string]bool{}
	for _, wallet := range wallets {
		wanted[wallet] = true
	}
	var minSlot, maxSlot int64
	count := 0
	for _, observation := range observations {
		if !wanted[strings.TrimSpace(observation.Wallet)] || observation.AcquisitionSlot <= 0 {
			continue
		}
		slot := observation.AcquisitionSlot
		if count == 0 || slot < minSlot {
			minSlot = slot
		}
		if count == 0 || slot > maxSlot {
			maxSlot = slot
		}
		count++
	}
	if count < 2 {
		return nil
	}
	spread := maxSlot - minSlot
	return &spread
}

func uniqueFundingStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
