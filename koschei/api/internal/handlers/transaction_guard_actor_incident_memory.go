package handlers

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
	transactionGuardActorIncidentMemoryVersion = "koschei-actor-incident-memory-v1"
	transactionGuardActorIncidentTokenLimit    = 64
	transactionGuardActorIncidentVerdictLimit  = 240
)

type transactionGuardActorIncidentVerdict struct {
	ModuleID       string   `json:"module_id"`
	RiskLevel      string   `json:"risk_level"`
	RiskIndex      int      `json:"risk_index"`
	Grade          string   `json:"grade,omitempty"`
	Verdict        string   `json:"verdict,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	Source         string   `json:"source,omitempty"`
	ObservedAt     string   `json:"observed_at"`
	Evidence       []string `json:"evidence"`
}

type transactionGuardActorIncidentToken struct {
	TokenMint          string                                  `json:"token_mint"`
	ActorSubjects      []string                                `json:"actor_subjects"`
	ActorEvidenceCount int                                     `json:"actor_evidence_count"`
	SignedVerdictCount int                                     `json:"signed_verdict_count"`
	HighestRiskLevel   string                                  `json:"highest_risk_level,omitempty"`
	HighestRiskIndex   int                                     `json:"highest_risk_index"`
	MaterialRiskHistory bool                                   `json:"material_risk_history"`
	Verdicts           []transactionGuardActorIncidentVerdict `json:"verdicts"`
}

type transactionGuardActorIncidentMemory struct {
	Version                 string                               `json:"version"`
	Network                 string                               `json:"network"`
	TransactionFingerprint  string                               `json:"transaction_fingerprint"`
	Status                  string                               `json:"status"`
	Complete                bool                                 `json:"complete"`
	ActorMemoryStatus       string                               `json:"actor_memory_status"`
	LinkedTokenCount        int                                  `json:"linked_token_count"`
	SignedHistoryTokenCount int                                  `json:"signed_history_token_count"`
	MaterialRiskTokenCount  int                                  `json:"material_risk_token_count"`
	Tokens                  []transactionGuardActorIncidentToken `json:"tokens"`
	Limitations             []string                             `json:"limitations"`
	EvidenceHashSHA256      string                               `json:"evidence_hash_sha256"`
	VerdictAuthority        bool                                 `json:"verdict_authority"`
	RealWorldIdentityClaim  bool                                 `json:"real_world_identity_claim"`
	WrongdoingClaim         bool                                 `json:"wrongdoing_claim"`
	SafetyClaim             bool                                 `json:"safety_claim"`
}

type transactionGuardActorIncidentVerdictRow struct {
	TokenMint       string
	ModuleID        string
	RiskIndex       int
	RiskLevel       string
	Grade           string
	Verdict         string
	Recommendation  string
	Evidence        []string
	Source          string
	ObservedAt      time.Time
}

// collectTransactionGuardActorIncidentMemory joins two already-persistent
// Koschei evidence stores without making an identity or wrongdoing inference:
//
//   exact transaction subject -> security_actor_evidence -> token mint
//   token mint -> signed security_radar_verdicts history
//
// The result is pre-signing historical context only. It never emits a finding,
// score, grade or Guard action and therefore cannot block a transaction by itself.
func (h *Handler) collectTransactionGuardActorIncidentMemory(ctx context.Context, network, fingerprint string, actorMemory transactionGuardActorMemoryGraph) transactionGuardActorIncidentMemory {
	out := transactionGuardActorIncidentMemory{
		Version: transactionGuardActorIncidentMemoryVersion,
		Network: strings.TrimSpace(network), TransactionFingerprint: strings.TrimSpace(fingerprint),
		Status: "no_linked_tokens", Complete: true, ActorMemoryStatus: actorMemory.Status,
		Tokens: []transactionGuardActorIncidentToken{}, Limitations: []string{},
		VerdictAuthority: false, RealWorldIdentityClaim: false, WrongdoingClaim: false, SafetyClaim: false,
	}
	if out.Network == "" {
		out.Network = "solana-mainnet"
	}
	if !actorMemory.Complete {
		out.Status = "actor_memory_unavailable"
		out.Complete = false
		out.Limitations = append(out.Limitations, "Persistent actor memory is incomplete; incident-memory projection was withheld.")
		out.EvidenceHashSHA256 = transactionGuardActorIncidentMemoryHash(out)
		return out
	}

	links := transactionGuardActorIncidentLinks(actorMemory)
	if len(links) == 0 {
		out.EvidenceHashSHA256 = transactionGuardActorIncidentMemoryHash(out)
		return out
	}
	if len(links) > transactionGuardActorIncidentTokenLimit {
		links = firstTransactionGuardActorIncidentLinks(links, transactionGuardActorIncidentTokenLimit)
		out.Complete = false
		out.Limitations = append(out.Limitations, "Actor-linked token set exceeded the bounded pre-signing incident-memory limit; only the deterministic first subset was queried.")
	}
	out.LinkedTokenCount = len(links)

	db := (*sql.DB)(nil)
	if h != nil {
		db = h.DBRead
		if db == nil {
			db = h.DB
		}
	}
	if db == nil {
		return unavailableTransactionGuardActorIncidentMemory(out, "signed security-history database is unavailable")
	}
	queryCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	if !ownerTableExists(queryCtx, db, "security_radar_verdicts") {
		return unavailableTransactionGuardActorIncidentMemory(out, "security_radar_verdicts is unavailable")
	}

	rows, err := queryTransactionGuardActorIncidentVerdicts(queryCtx, db, out.Network, links)
	if err != nil {
		return unavailableTransactionGuardActorIncidentMemory(out, "signed token security-history query failed")
	}
	out = aggregateTransactionGuardActorIncidentMemory(out, links, rows)
	out.Limitations = append(out.Limitations,
		"Incident Memory requires an exact retained actor-to-token relation and a Koschei-signed token verdict; neither relation implies common real-world identity or intent.",
		"Material risk history means the linked token has a signed HIGH or CRITICAL historical security verdict; it is historical context, not proof that the current transaction subject caused that verdict.",
		"A no-history result means Koschei has no matching signed verdict in retained memory; it is not a safety claim.",
	)
	out.EvidenceHashSHA256 = transactionGuardActorIncidentMemoryHash(out)
	return out
}

func transactionGuardActorIncidentLinks(actorMemory transactionGuardActorMemoryGraph) map[string][]string {
	links := map[string][]string{}
	for _, subject := range actorMemory.Subjects {
		address := strings.TrimSpace(subject.Address)
		if address == "" {
			continue
		}
		for _, rawMint := range subject.TokenMints {
			mint := strings.TrimSpace(rawMint)
			if !looksLikeGuardPubkey(mint) {
				continue
			}
			links[mint] = appendUniqueSortedString(links[mint], address)
		}
	}
	return links
}

func firstTransactionGuardActorIncidentLinks(values map[string][]string, limit int) map[string][]string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	out := make(map[string][]string, len(keys))
	for _, key := range keys {
		out[key] = append([]string{}, values[key]...)
	}
	return out
}

func queryTransactionGuardActorIncidentVerdicts(ctx context.Context, db *sql.DB, network string, links map[string][]string) ([]transactionGuardActorIncidentVerdictRow, error) {
	if db == nil || len(links) == 0 {
		return []transactionGuardActorIncidentVerdictRow{}, nil
	}
	mints := make([]string, 0, len(links))
	for mint := range links {
		mints = append(mints, strings.TrimSpace(mint))
	}
	sort.Strings(mints)
	args := []any{strings.TrimSpace(network)}
	placeholders := make([]string, 0, len(mints))
	for index, mint := range mints {
		args = append(args, strings.ToLower(mint))
		placeholders = append(placeholders, fmt.Sprintf("$%d", index+2))
	}
	query := `
		SELECT target,module_id,risk_index,risk_level,grade,verdict,recommendation,evidence,source,created_at
		FROM security_radar_verdicts
		WHERE network=$1 AND signed=true
		  AND lower(target) IN (` + strings.Join(placeholders, ",") + `)
		ORDER BY created_at DESC
		LIMIT ` + fmt.Sprintf("%d", transactionGuardActorIncidentVerdictLimit)
	result, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer result.Close()
	rows := []transactionGuardActorIncidentVerdictRow{}
	for result.Next() {
		var target, moduleID, riskLevel, grade, verdict, recommendation, source sql.NullString
		var riskIndex sql.NullInt64
		var evidenceRaw []byte
		var observedAt time.Time
		if err := result.Scan(&target, &moduleID, &riskIndex, &riskLevel, &grade, &verdict, &recommendation, &evidenceRaw, &source, &observedAt); err != nil {
			return nil, err
		}
		rows = append(rows, transactionGuardActorIncidentVerdictRow{
			TokenMint: strings.TrimSpace(target.String), ModuleID: strings.TrimSpace(moduleID.String),
			RiskIndex: int(riskIndex.Int64), RiskLevel: normalizedThreatRiskLevel(riskLevel.String, int(riskIndex.Int64)),
			Grade: strings.TrimSpace(grade.String), Verdict: strings.TrimSpace(verdict.String),
			Recommendation: strings.TrimSpace(recommendation.String), Evidence: transactionGuardThreatEvidenceStrings(evidenceRaw),
			Source: strings.TrimSpace(source.String), ObservedAt: observedAt.UTC(),
		})
	}
	return rows, result.Err()
}

func aggregateTransactionGuardActorIncidentMemory(out transactionGuardActorIncidentMemory, links map[string][]string, rows []transactionGuardActorIncidentVerdictRow) transactionGuardActorIncidentMemory {
	tokens := map[string]*transactionGuardActorIncidentToken{}
	canonical := map[string]string{}
	for mint, subjects := range links {
		key := strings.ToLower(strings.TrimSpace(mint))
		if key == "" {
			continue
		}
		canonical[key] = strings.TrimSpace(mint)
		tokens[key] = &transactionGuardActorIncidentToken{
			TokenMint: strings.TrimSpace(mint), ActorSubjects: append([]string{}, subjects...),
			ActorEvidenceCount: len(subjects), HighestRiskLevel: "low", Verdicts: []transactionGuardActorIncidentVerdict{},
		}
	}
	for _, row := range rows {
		key := strings.ToLower(strings.TrimSpace(row.TokenMint))
		token := tokens[key]
		if token == nil {
			continue
		}
		token.SignedVerdictCount++
		if riskRank(row.RiskLevel, row.RiskIndex) > riskRank(token.HighestRiskLevel, token.HighestRiskIndex) {
			token.HighestRiskLevel = normalizedThreatRiskLevel(row.RiskLevel, row.RiskIndex)
			token.HighestRiskIndex = row.RiskIndex
		}
		if len(token.Verdicts) < 8 {
			token.Verdicts = append(token.Verdicts, transactionGuardActorIncidentVerdict{
				ModuleID: row.ModuleID, RiskLevel: row.RiskLevel, RiskIndex: row.RiskIndex, Grade: row.Grade,
				Verdict: row.Verdict, Recommendation: row.Recommendation, Source: row.Source,
				ObservedAt: row.ObservedAt.Format(time.RFC3339), Evidence: append([]string{}, row.Evidence...),
			})
		}
	}

	keys := make([]string, 0, len(tokens))
	for key := range tokens {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		token := tokens[key]
		if token == nil {
			continue
		}
		level := normalizedThreatRiskLevel(token.HighestRiskLevel, token.HighestRiskIndex)
		token.HighestRiskLevel = level
		token.MaterialRiskHistory = level == "high" || level == "critical"
		if token.SignedVerdictCount > 0 {
			out.SignedHistoryTokenCount++
		}
		if token.MaterialRiskHistory {
			out.MaterialRiskTokenCount++
		}
		out.Tokens = append(out.Tokens, *token)
	}
	_ = canonical
	out.Status = "linked_tokens_no_signed_history"
	if out.SignedHistoryTokenCount > 0 {
		out.Status = "signed_security_history_observed"
	}
	if out.MaterialRiskTokenCount > 0 {
		out.Status = "material_signed_risk_history_observed"
	}
	return out
}

func unavailableTransactionGuardActorIncidentMemory(out transactionGuardActorIncidentMemory, reason string) transactionGuardActorIncidentMemory {
	out.Status = "source_unavailable"
	out.Complete = false
	out.Limitations = append(out.Limitations, strings.TrimSpace(reason), "Incident-memory unavailability does not imply safety or risk.")
	out.EvidenceHashSHA256 = transactionGuardActorIncidentMemoryHash(out)
	return out
}

func transactionGuardActorIncidentMemoryHash(value transactionGuardActorIncidentMemory) string {
	value.EvidenceHashSHA256 = ""
	payload, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}
