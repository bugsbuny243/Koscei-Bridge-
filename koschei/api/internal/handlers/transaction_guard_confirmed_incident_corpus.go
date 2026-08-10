package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	transactionGuardConfirmedIncidentCorpusVersion = "koschei-guard-confirmed-incidents-v1"
	transactionGuardConfirmedIncidentRowLimit      = 120
)

type transactionGuardConfirmedIncident struct {
	IncidentKey        string   `json:"incident_key"`
	Target             string   `json:"target"`
	ActorWallet        string   `json:"actor_wallet"`
	TransactionRoles   []string `json:"transaction_roles"`
	EventKind          string   `json:"event_kind"`
	SourceRuleID       string   `json:"source_rule_id"`
	EventSignature     string   `json:"event_signature"`
	EventSlot          int64    `json:"event_slot"`
	EventObservedAt    string   `json:"event_observed_at"`
	VerdictSignature   string   `json:"verdict_signature"`
	VerdictRuleVersion string   `json:"verdict_rule_version"`
	Grade              string   `json:"grade"`
	RiskIndex          int      `json:"risk_index"`
	RiskLevel          string   `json:"risk_level"`
	Verdict            string   `json:"verdict,omitempty"`
	Recommendation     string   `json:"recommendation,omitempty"`
	RecordHash         string   `json:"record_hash"`
	VersionCount       int      `json:"version_count"`
	LatestCreatedAt    string   `json:"latest_created_at"`
}

type transactionGuardConfirmedIncidentCorpus struct {
	Version                string                               `json:"version"`
	Network                string                               `json:"network"`
	TransactionFingerprint string                               `json:"transaction_fingerprint"`
	Status                 string                               `json:"status"`
	Complete               bool                                 `json:"complete"`
	SubjectsChecked        int                                  `json:"subjects_checked"`
	ActorsMatched          int                                  `json:"actors_matched"`
	IncidentCount          int                                  `json:"incident_count"`
	CriticalIncidentCount  int                                  `json:"critical_incident_count"`
	Incidents              []transactionGuardConfirmedIncident `json:"incidents"`
	Limitations            []string                             `json:"limitations"`
	VerdictAuthority       bool                                 `json:"verdict_authority"`
	CausationClaim         bool                                 `json:"causation_claim"`
	RealWorldIdentityClaim bool                                 `json:"real_world_identity_claim"`
	WrongdoingClaim        bool                                 `json:"wrongdoing_claim"`
	SafetyClaim            bool                                 `json:"safety_claim"`
}

func (h *Handler) collectTransactionGuardConfirmedIncidentCorpus(ctx context.Context, network, fingerprint string, decoded transactionGuardDecodedTransaction, wallet string) transactionGuardConfirmedIncidentCorpus {
	candidates := transactionGuardActorMemoryCandidates(decoded, wallet)
	out := transactionGuardConfirmedIncidentCorpus{
		Version: transactionGuardConfirmedIncidentCorpusVersion,
		Network: strings.TrimSpace(network), TransactionFingerprint: strings.TrimSpace(fingerprint),
		Status: "no_subjects", Complete: true, SubjectsChecked: len(candidates),
		Incidents: []transactionGuardConfirmedIncident{}, Limitations: []string{},
		VerdictAuthority: false, CausationClaim: false, RealWorldIdentityClaim: false,
		WrongdoingClaim: false, SafetyClaim: false,
	}
	if out.Network == "" {
		out.Network = "solana-mainnet"
	}
	if len(candidates) == 0 {
		return out
	}

	db := (*sql.DB)(nil)
	if h != nil {
		db = h.DBRead
		if db == nil {
			db = h.DB
		}
	}
	if db == nil {
		out.Status = "source_unavailable"
		out.Complete = false
		out.Limitations = append(out.Limitations, "Verified incident corpus database is unavailable.")
		return out
	}

	queryCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	if !ownerTableExists(queryCtx, db, "security_incident_corpus") {
		out.Status = "source_unavailable"
		out.Complete = false
		out.Limitations = append(out.Limitations, "Verified incident corpus schema is unavailable.")
		return out
	}

	rolesByActor := map[string][]string{}
	keys := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		actor := strings.TrimSpace(candidate.Address)
		if actor == "" {
			continue
		}
		if _, ok := rolesByActor[actor]; !ok {
			keys = append(keys, actor)
		}
		for _, role := range candidate.Roles {
			rolesByActor[actor] = appendUniqueSortedString(rolesByActor[actor], role)
		}
	}
	if len(keys) == 0 {
		return out
	}
	sort.Strings(keys)

	args := []any{out.Network}
	placeholders := make([]string, 0, len(keys))
	for index, actor := range keys {
		args = append(args, actor)
		placeholders = append(placeholders, fmt.Sprintf("$%d", index+2))
	}
	query := `
		WITH ranked AS (
			SELECT c.*,
			       count(*) OVER (PARTITION BY actor_wallet,target,event_kind,event_signature) AS version_count,
			       row_number() OVER (
			           PARTITION BY actor_wallet,target,event_kind,event_signature
			           ORDER BY verdict_updated_at DESC,created_at DESC,id DESC
			       ) AS version_rank
			FROM security_incident_corpus c
			WHERE network=$1 AND actor_wallet IN (` + strings.Join(placeholders, ",") + `)
		)
		SELECT incident_key,target,actor_wallet,event_kind,source_rule_id,event_signature,event_slot,event_observed_at,
		       verdict_signature,verdict_rule_version,grade,risk_index,risk_level,verdict,recommendation,record_hash,
		       version_count,created_at
		FROM ranked
		WHERE version_rank=1
		ORDER BY CASE risk_level WHEN 'critical' THEN 0 ELSE 1 END,risk_index DESC,created_at DESC
		LIMIT ` + fmt.Sprintf("%d", transactionGuardConfirmedIncidentRowLimit)
	rows, err := db.QueryContext(queryCtx, query, args...)
	if err != nil {
		out.Status = "source_unavailable"
		out.Complete = false
		out.Limitations = append(out.Limitations, "Verified incident corpus query failed within the Guard evidence budget.")
		return out
	}
	defer rows.Close()
	matchedActors := map[string]bool{}
	for rows.Next() {
		var item transactionGuardConfirmedIncident
		var observedAt, createdAt time.Time
		if err := rows.Scan(
			&item.IncidentKey, &item.Target, &item.ActorWallet, &item.EventKind, &item.SourceRuleID,
			&item.EventSignature, &item.EventSlot, &observedAt, &item.VerdictSignature, &item.VerdictRuleVersion,
			&item.Grade, &item.RiskIndex, &item.RiskLevel, &item.Verdict, &item.Recommendation, &item.RecordHash,
			&item.VersionCount, &createdAt,
		); err != nil {
			out.Status = "source_unavailable"
			out.Complete = false
			out.Limitations = append(out.Limitations, "Verified incident corpus row decoding failed.")
			return out
		}
		item.ActorWallet = strings.TrimSpace(item.ActorWallet)
		item.TransactionRoles = append([]string{}, rolesByActor[item.ActorWallet]...)
		item.EventObservedAt = observedAt.UTC().Format(time.RFC3339)
		item.LatestCreatedAt = createdAt.UTC().Format(time.RFC3339)
		out.Incidents = append(out.Incidents, item)
		matchedActors[item.ActorWallet] = true
		if item.RiskLevel == "critical" {
			out.CriticalIncidentCount++
		}
	}
	if err := rows.Err(); err != nil {
		out.Status = "source_unavailable"
		out.Complete = false
		out.Limitations = append(out.Limitations, "Verified incident corpus cursor failed.")
		return out
	}
	out.ActorsMatched = len(matchedActors)
	out.IncidentCount = len(out.Incidents)
	out.Status = "complete_no_matches"
	if out.IncidentCount > 0 {
		out.Status = "verified_incidents_observed"
	}
	out.Limitations = append(out.Limitations,
		"A corpus match requires a transaction-referenced VERIFIED actor event and a Koschei-signed material final token verdict.",
		"The conjunction is historical context only: it does not prove that the matched actor caused the token verdict or that the actor has malicious intent in the current transaction.",
		"No match is not a safety claim and may reflect incomplete historical collection.",
	)
	return out
}
