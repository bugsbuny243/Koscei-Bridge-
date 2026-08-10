package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	FundingClusterOutcomeMemoryVersion = "koschei-funding-outcome-memory-v1"
	fundingOutcomeVerdictRowLimit      = 320
)

type FundingClusterOutcomeVerdict struct {
	ModuleID       string `json:"module_id"`
	RiskLevel      string `json:"risk_level"`
	RiskIndex      int    `json:"risk_index"`
	Grade          string `json:"grade,omitempty"`
	Verdict        string `json:"verdict,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
	Source         string `json:"source,omitempty"`
	ObservedAt     string `json:"observed_at"`
}

type FundingClusterOutcomeTarget struct {
	Target              string                         `json:"target"`
	SignedVerdictCount  int                            `json:"signed_verdict_count"`
	HighestRiskLevel    string                         `json:"highest_risk_level,omitempty"`
	HighestRiskIndex    int                            `json:"highest_risk_index"`
	MaterialRiskHistory bool                           `json:"material_risk_history"`
	Verdicts            []FundingClusterOutcomeVerdict `json:"verdicts"`
}

type FundingClusterOutcomeSource struct {
	FundingSource            string                        `json:"funding_source"`
	HistoricalTargetCount    int                           `json:"historical_target_count"`
	SignedHistoryTargetCount int                           `json:"signed_history_target_count"`
	MaterialRiskTargetCount  int                           `json:"material_risk_target_count"`
	Targets                  []FundingClusterOutcomeTarget `json:"targets"`
}

type FundingClusterOutcomeMemory struct {
	Version                  string                        `json:"version"`
	Network                  string                        `json:"network"`
	CurrentTarget            string                        `json:"current_target"`
	Status                   string                        `json:"status"`
	Complete                 bool                          `json:"complete"`
	SourceCount              int                           `json:"source_count"`
	HistoricalTargetCount    int                           `json:"historical_target_count"`
	SignedHistoryTargetCount int                           `json:"signed_history_target_count"`
	MaterialRiskTargetCount  int                           `json:"material_risk_target_count"`
	Sources                  []FundingClusterOutcomeSource `json:"sources"`
	Limitations              []string                      `json:"limitations"`
	EvidenceHashSHA256       string                        `json:"evidence_hash_sha256"`
	VerdictAuthority         bool                          `json:"verdict_authority"`
	RealWorldIdentityClaim   bool                          `json:"real_world_identity_claim"`
	WrongdoingClaim          bool                          `json:"wrongdoing_claim"`
	SafetyClaim              bool                          `json:"safety_claim"`
}

type fundingClusterOutcomeVerdictRow struct {
	Target         string
	ModuleID       string
	RiskIndex      int
	RiskLevel      string
	Grade          string
	Verdict        string
	Recommendation string
	Source         string
	ObservedAt     time.Time
}

// LoadFundingClusterOutcomeMemory adds historical outcome context to an already
// established funding-recurrence projection. It performs no RPC call and does
// not change a Radar grade. A shared funder remains an on-chain relationship;
// historical risk on another token is not proof the funder caused that risk.
func LoadFundingClusterOutcomeMemory(ctx context.Context, db *sql.DB, recurrence FundingRecurrenceAnalysis) FundingClusterOutcomeMemory {
	out := FundingClusterOutcomeMemory{
		Version: FundingClusterOutcomeMemoryVersion,
		Network: normalizeRadarNetwork(recurrence.Network), CurrentTarget: strings.TrimSpace(recurrence.CurrentTarget),
		Status: "no_recurrent_funders", Complete: true, Sources: []FundingClusterOutcomeSource{}, Limitations: []string{},
		VerdictAuthority: false, RealWorldIdentityClaim: false, WrongdoingClaim: false, SafetyClaim: false,
	}
	if !recurrence.Available && recurrence.Status == "unavailable" {
		out.Status = "funding_recurrence_unavailable"
		out.Complete = false
		out.Limitations = append(out.Limitations, "Funding recurrence is unavailable; outcome memory was withheld.")
		out.EvidenceHashSHA256 = fundingClusterOutcomeMemoryHash(out)
		return out
	}
	links := fundingClusterOutcomeLinks(recurrence)
	if len(links) == 0 {
		out.EvidenceHashSHA256 = fundingClusterOutcomeMemoryHash(out)
		return out
	}
	out.SourceCount = len(links)
	if db == nil {
		return unavailableFundingClusterOutcomeMemory(out, "signed Security Radar verdict database is unavailable")
	}

	queryCtx, cancel := context.WithTimeout(ctx, fundingClusterStoreTimeout)
	defer cancel()
	rows, err := queryFundingClusterOutcomeVerdicts(queryCtx, db, out.Network, links)
	if err != nil {
		return unavailableFundingClusterOutcomeMemory(out, "signed token verdict history could not be read")
	}
	out = aggregateFundingClusterOutcomeMemory(out, links, rows)
	out.Limitations = append(out.Limitations,
		"Funding Outcome Memory uses previously persisted funding recurrence plus Koschei-signed token verdict history.",
		"A HIGH or CRITICAL historical verdict on a linked token is context only; it does not prove the funding source caused, controlled or intended that outcome.",
		"No signed-history match is not a safety claim and may reflect incomplete Koschei collection coverage.",
	)
	out.EvidenceHashSHA256 = fundingClusterOutcomeMemoryHash(out)
	return out
}

func fundingClusterOutcomeLinks(recurrence FundingRecurrenceAnalysis) map[string][]string {
	links := map[string][]string{}
	for _, source := range recurrence.Sources {
		funder := strings.TrimSpace(source.FundingSource)
		if funder == "" || source.DistinctTargets < 2 || !source.ReferencesComplete {
			continue
		}
		for _, rawTarget := range source.OtherTargets {
			target := strings.TrimSpace(rawTarget)
			if target == "" || target == strings.TrimSpace(recurrence.CurrentTarget) {
				continue
			}
			links[funder] = appendFundingOutcomeUnique(links[funder], target)
		}
	}
	return links
}

func queryFundingClusterOutcomeVerdicts(ctx context.Context, db *sql.DB, network string, links map[string][]string) ([]fundingClusterOutcomeVerdictRow, error) {
	if db == nil || len(links) == 0 {
		return []fundingClusterOutcomeVerdictRow{}, nil
	}
	targets := []string{}
	for _, sourceTargets := range links {
		targets = append(targets, sourceTargets...)
	}
	targets = appendFundingOutcomeUnique(nil, targets...)
	if len(targets) == 0 {
		return []fundingClusterOutcomeVerdictRow{}, nil
	}
	args := []any{strings.TrimSpace(network)}
	placeholders := make([]string, 0, len(targets))
	for index, target := range targets {
		args = append(args, strings.ToLower(strings.TrimSpace(target)))
		placeholders = append(placeholders, fmt.Sprintf("$%d", index+2))
	}
	query := `
		SELECT target,module_id,risk_index,risk_level,grade,verdict,recommendation,source,created_at
		FROM security_radar_verdicts
		WHERE network=$1 AND signed=true
		  AND lower(target) IN (` + strings.Join(placeholders, ",") + `)
		ORDER BY created_at DESC
		LIMIT ` + fmt.Sprintf("%d", fundingOutcomeVerdictRowLimit)
	result, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer result.Close()
	rows := []fundingClusterOutcomeVerdictRow{}
	for result.Next() {
		var target, moduleID, riskLevel, grade, verdict, recommendation, source sql.NullString
		var riskIndex sql.NullInt64
		var observedAt time.Time
		if err := result.Scan(&target, &moduleID, &riskIndex, &riskLevel, &grade, &verdict, &recommendation, &source, &observedAt); err != nil {
			return nil, err
		}
		rows = append(rows, fundingClusterOutcomeVerdictRow{
			Target: strings.TrimSpace(target.String), ModuleID: strings.TrimSpace(moduleID.String), RiskIndex: int(riskIndex.Int64),
			RiskLevel: fundingOutcomeRiskLevel(riskLevel.String, int(riskIndex.Int64)), Grade: strings.TrimSpace(grade.String),
			Verdict: strings.TrimSpace(verdict.String), Recommendation: strings.TrimSpace(recommendation.String),
			Source: strings.TrimSpace(source.String), ObservedAt: observedAt.UTC(),
		})
	}
	return rows, result.Err()
}

func aggregateFundingClusterOutcomeMemory(out FundingClusterOutcomeMemory, links map[string][]string, rows []fundingClusterOutcomeVerdictRow) FundingClusterOutcomeMemory {
	rowsByTarget := map[string][]fundingClusterOutcomeVerdictRow{}
	for _, row := range rows {
		key := strings.ToLower(strings.TrimSpace(row.Target))
		if key != "" {
			rowsByTarget[key] = append(rowsByTarget[key], row)
		}
	}
	funders := make([]string, 0, len(links))
	for funder := range links {
		funders = append(funders, funder)
	}
	sort.Strings(funders)
	seenHistorical := map[string]bool{}
	seenSigned := map[string]bool{}
	seenMaterial := map[string]bool{}
	for _, funder := range funders {
		targets := append([]string{}, links[funder]...)
		sort.Strings(targets)
		source := FundingClusterOutcomeSource{FundingSource: funder, HistoricalTargetCount: len(targets), Targets: []FundingClusterOutcomeTarget{}}
		for _, target := range targets {
			key := strings.ToLower(strings.TrimSpace(target))
			item := FundingClusterOutcomeTarget{Target: target, HighestRiskLevel: "low", Verdicts: []FundingClusterOutcomeVerdict{}}
			seenHistorical[key] = true
			for _, row := range rowsByTarget[key] {
				item.SignedVerdictCount++
				if fundingOutcomeRiskRank(row.RiskLevel, row.RiskIndex) > fundingOutcomeRiskRank(item.HighestRiskLevel, item.HighestRiskIndex) {
					item.HighestRiskLevel = fundingOutcomeRiskLevel(row.RiskLevel, row.RiskIndex)
					item.HighestRiskIndex = row.RiskIndex
				}
				if len(item.Verdicts) < 8 {
					item.Verdicts = append(item.Verdicts, FundingClusterOutcomeVerdict{
						ModuleID: row.ModuleID, RiskLevel: row.RiskLevel, RiskIndex: row.RiskIndex, Grade: row.Grade,
						Verdict: row.Verdict, Recommendation: row.Recommendation, Source: row.Source, ObservedAt: row.ObservedAt.Format(time.RFC3339),
					})
				}
			}
			item.HighestRiskLevel = fundingOutcomeRiskLevel(item.HighestRiskLevel, item.HighestRiskIndex)
			item.MaterialRiskHistory = item.HighestRiskLevel == "high" || item.HighestRiskLevel == "critical"
			if item.SignedVerdictCount > 0 {
				source.SignedHistoryTargetCount++
				seenSigned[key] = true
			}
			if item.MaterialRiskHistory {
				source.MaterialRiskTargetCount++
				seenMaterial[key] = true
			}
			source.Targets = append(source.Targets, item)
		}
		out.Sources = append(out.Sources, source)
	}
	out.HistoricalTargetCount = len(seenHistorical)
	out.SignedHistoryTargetCount = len(seenSigned)
	out.MaterialRiskTargetCount = len(seenMaterial)
	out.Status = "recurrent_funders_no_signed_history"
	if out.SignedHistoryTargetCount > 0 {
		out.Status = "signed_outcome_history_observed"
	}
	if out.MaterialRiskTargetCount > 0 {
		out.Status = "material_signed_outcome_history_observed"
	}
	return out
}

func unavailableFundingClusterOutcomeMemory(out FundingClusterOutcomeMemory, reason string) FundingClusterOutcomeMemory {
	out.Status = "source_unavailable"
	out.Complete = false
	out.Limitations = append(out.Limitations, strings.TrimSpace(reason), "Outcome-memory unavailability does not imply safety or risk.")
	out.EvidenceHashSHA256 = fundingClusterOutcomeMemoryHash(out)
	return out
}

func appendFundingOutcomeUnique(values []string, more ...string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = true
		}
	}
	for _, value := range more {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func fundingOutcomeRiskLevel(level string, index int) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	}
	switch {
	case index >= 80:
		return "critical"
	case index >= 60:
		return "high"
	case index >= 30:
		return "medium"
	default:
		return "low"
	}
}

func fundingOutcomeRiskRank(level string, index int) int {
	switch fundingOutcomeRiskLevel(level, index) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func fundingClusterOutcomeMemoryHash(value FundingClusterOutcomeMemory) string {
	value.EvidenceHashSHA256 = ""
	payload, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}
