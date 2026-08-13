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
	transactionGuardActorMemoryGraphVersion = "koschei-actor-memory-graph-v1"
	transactionGuardActorMemorySubjectLimit = 48
	transactionGuardActorMemoryRowLimit     = 240
)

type transactionGuardActorMemoryEvidence struct {
	ActorRole          string `json:"actor_role"`
	Relation           string `json:"relation"`
	VerificationStatus string `json:"verification_status"`
	CounterpartKind    string `json:"counterpart_kind,omitempty"`
	CounterpartID      string `json:"counterpart_id,omitempty"`
	TokenMint          string `json:"token_mint,omitempty"`
	Signature          string `json:"signature,omitempty"`
	Slot               int64  `json:"slot,omitempty"`
	Source             string `json:"source,omitempty"`
	LastObservedAt     string `json:"last_observed_at"`
}

type transactionGuardActorMemorySubject struct {
	Address          string                                `json:"address"`
	TransactionRoles []string                              `json:"transaction_roles"`
	Matched          bool                                  `json:"matched"`
	EvidenceCount    int                                   `json:"evidence_count"`
	VerifiedCount    int                                   `json:"verified_count"`
	ObservedCount    int                                   `json:"observed_count"`
	ActorRoles       []string                              `json:"actor_roles"`
	Relations        []string                              `json:"relations"`
	TokenMints       []string                              `json:"token_mints"`
	Evidence         []transactionGuardActorMemoryEvidence `json:"evidence"`
}

type transactionGuardActorMemoryGraph struct {
	Version                string                               `json:"version"`
	Network                string                               `json:"network"`
	TransactionFingerprint string                               `json:"transaction_fingerprint"`
	Status                 string                               `json:"status"`
	Complete               bool                                 `json:"complete"`
	SubjectsChecked        int                                  `json:"subjects_checked"`
	SubjectsMatched        int                                  `json:"subjects_matched"`
	VerifiedEvidenceCount  int                                  `json:"verified_evidence_count"`
	ObservedEvidenceCount  int                                  `json:"observed_evidence_count"`
	Subjects               []transactionGuardActorMemorySubject `json:"subjects"`
	Limitations            []string                             `json:"limitations"`
	EvidenceHashSHA256     string                               `json:"evidence_hash_sha256"`
	VerdictAuthority       bool                                 `json:"verdict_authority"`
	RealWorldIdentityClaim bool                                 `json:"real_world_identity_claim"`
	SafetyClaim            bool                                 `json:"safety_claim"`
}

type transactionGuardActorMemoryRow struct {
	Address            string
	ActorRole          string
	Relation           string
	VerificationStatus string
	CounterpartKind    string
	CounterpartID      string
	TokenMint          string
	Signature          string
	Slot               int64
	Source             string
	LastObservedAt     time.Time
}

// collectTransactionGuardActorMemoryGraph is an evidence-context layer only.
// ACTOR_INVESTIGATION_ENGINE.md questions 6, 9 and 10; actor ruleset v1.0.
// It performs exact on-chain address matches against persistent actor memory and
// deliberately does not add a finding, score, grade or block decision.
func (h *Handler) collectTransactionGuardActorMemoryGraph(ctx context.Context, network, fingerprint string, decoded transactionGuardDecodedTransaction, wallet string) transactionGuardActorMemoryGraph {
	candidates := transactionGuardActorMemoryCandidates(decoded, wallet)
	graph := transactionGuardActorMemoryGraph{
		Version: transactionGuardActorMemoryGraphVersion,
		Network: strings.TrimSpace(network), TransactionFingerprint: strings.TrimSpace(fingerprint),
		Status: "complete_no_matches", Complete: true, SubjectsChecked: len(candidates),
		Subjects: []transactionGuardActorMemorySubject{}, Limitations: []string{},
		VerdictAuthority: false, RealWorldIdentityClaim: false, SafetyClaim: false,
	}
	if graph.Network == "" {
		graph.Network = "solana-mainnet"
	}
	if len(candidates) == 0 {
		graph.Status = "no_subjects"
		graph.EvidenceHashSHA256 = transactionGuardActorMemoryGraphHash(graph)
		return graph
	}

	db := (*sql.DB)(nil)
	if h != nil {
		db = h.DBRead
		if db == nil {
			db = h.DB
		}
	}
	if db == nil {
		return unavailableTransactionGuardActorMemoryGraph(graph, "persistent actor-memory database is unavailable")
	}
	queryCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	if !ownerTableExists(queryCtx, db, "security_actor_evidence") {
		return unavailableTransactionGuardActorMemoryGraph(graph, "security_actor_evidence is unavailable")
	}
	rows, err := queryTransactionGuardActorMemoryRows(queryCtx, db, graph.Network, candidates)
	if err != nil {
		return unavailableTransactionGuardActorMemoryGraph(graph, "persistent actor-memory query failed")
	}
	graph = aggregateTransactionGuardActorMemoryGraph(graph, candidates, rows)
	graph.Limitations = append(graph.Limitations,
		"Actor Memory Graph uses exact on-chain address matches from Koschei persistent actor evidence.",
		"VERIFIED proves the recorded on-chain relation only; OBSERVED is context only. Neither status proves common real-world identity, intent or wrongdoing.",
		"A no-match result means Koschei has no retained evidence for the checked subjects; it is not a safety claim.",
	)
	graph.EvidenceHashSHA256 = transactionGuardActorMemoryGraphHash(graph)
	return graph
}

func transactionGuardActorMemoryCandidates(decoded transactionGuardDecodedTransaction, wallet string) []transactionGuardThreatCandidate {
	base := transactionGuardV3ThreatCandidates(decoded, wallet)
	roles := map[string]map[string]bool{}
	canonical := map[string]string{}
	add := func(address, role string) {
		address = strings.TrimSpace(address)
		role = strings.TrimSpace(role)
		if !looksLikeGuardPubkey(address) || role == "" || address == strings.TrimSpace(wallet) {
			return
		}
		key := strings.ToLower(address)
		if roles[key] == nil {
			roles[key] = map[string]bool{}
			canonical[key] = address
		}
		roles[key][role] = true
	}
	for _, candidate := range base {
		for _, role := range candidate.Roles {
			add(candidate.Address, role)
		}
	}
	for _, account := range decoded.AutomaticBalance.Accounts {
		add(account.PreTokenOwner, "pre_token_owner")
		add(account.PostTokenOwner, "post_token_owner")
	}
	for _, operation := range decoded.TokenOperations {
		add(operation.Authority, "token_authority")
		add(operation.Delegate, "token_delegate")
		if operation.NewAuthority != "revoked" {
			add(operation.NewAuthority, "new_token_authority")
		}
	}
	keys := make([]string, 0, len(roles))
	for key := range roles {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > transactionGuardActorMemorySubjectLimit {
		keys = keys[:transactionGuardActorMemorySubjectLimit]
	}
	out := make([]transactionGuardThreatCandidate, 0, len(keys))
	for _, key := range keys {
		values := make([]string, 0, len(roles[key]))
		for role := range roles[key] {
			values = append(values, role)
		}
		sort.Strings(values)
		out = append(out, transactionGuardThreatCandidate{Address: canonical[key], Roles: values})
	}
	return out
}

func queryTransactionGuardActorMemoryRows(ctx context.Context, db *sql.DB, network string, candidates []transactionGuardThreatCandidate) ([]transactionGuardActorMemoryRow, error) {
	if db == nil || len(candidates) == 0 {
		return nil, nil
	}
	args := []any{strings.TrimSpace(network)}
	placeholders := make([]string, 0, len(candidates))
	for index, candidate := range candidates {
		args = append(args, strings.ToLower(strings.TrimSpace(candidate.Address)))
		placeholders = append(placeholders, fmt.Sprintf("$%d", index+2))
	}
	query := `
		SELECT actor_wallet,actor_role,relation,verification_status,counterpart_kind,counterpart_id,
		       COALESCE(token_mint,''),COALESCE(signature,''),COALESCE(slot,0),COALESCE(source,''),last_observed_at
		FROM security_actor_evidence
		WHERE network=$1
		  AND lower(actor_wallet) IN (` + strings.Join(placeholders, ",") + `)
		  AND verification_status IN ('verified','observed')
		ORDER BY last_observed_at DESC,id DESC
		LIMIT ` + fmt.Sprintf("%d", transactionGuardActorMemoryRowLimit)
	result, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer result.Close()
	rows := []transactionGuardActorMemoryRow{}
	for result.Next() {
		var row transactionGuardActorMemoryRow
		if err := result.Scan(&row.Address, &row.ActorRole, &row.Relation, &row.VerificationStatus, &row.CounterpartKind, &row.CounterpartID, &row.TokenMint, &row.Signature, &row.Slot, &row.Source, &row.LastObservedAt); err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, result.Err()
}

func aggregateTransactionGuardActorMemoryGraph(graph transactionGuardActorMemoryGraph, candidates []transactionGuardThreatCandidate, rows []transactionGuardActorMemoryRow) transactionGuardActorMemoryGraph {
	candidateByKey := map[string]transactionGuardThreatCandidate{}
	for _, candidate := range candidates {
		candidateByKey[strings.ToLower(strings.TrimSpace(candidate.Address))] = candidate
	}
	subjects := map[string]*transactionGuardActorMemorySubject{}
	for _, row := range rows {
		key := strings.ToLower(strings.TrimSpace(row.Address))
		candidate, ok := candidateByKey[key]
		if !ok {
			continue
		}
		subject := subjects[key]
		if subject == nil {
			subject = &transactionGuardActorMemorySubject{
				Address: candidate.Address, TransactionRoles: append([]string{}, candidate.Roles...), Matched: true,
				ActorRoles: []string{}, Relations: []string{}, TokenMints: []string{}, Evidence: []transactionGuardActorMemoryEvidence{},
			}
			subjects[key] = subject
		}
		subject.EvidenceCount++
		switch strings.ToLower(strings.TrimSpace(row.VerificationStatus)) {
		case "verified":
			subject.VerifiedCount++
			graph.VerifiedEvidenceCount++
		case "observed":
			subject.ObservedCount++
			graph.ObservedEvidenceCount++
		}
		subject.ActorRoles = appendUniqueSortedString(subject.ActorRoles, row.ActorRole)
		subject.Relations = appendUniqueSortedString(subject.Relations, row.Relation)
		subject.TokenMints = appendUniqueSortedString(subject.TokenMints, row.TokenMint)
		if len(subject.Evidence) < 12 {
			subject.Evidence = append(subject.Evidence, transactionGuardActorMemoryEvidence{
				ActorRole: row.ActorRole, Relation: row.Relation, VerificationStatus: row.VerificationStatus,
				CounterpartKind: row.CounterpartKind, CounterpartID: row.CounterpartID, TokenMint: row.TokenMint,
				Signature: row.Signature, Slot: row.Slot, Source: row.Source, LastObservedAt: row.LastObservedAt.UTC().Format(time.RFC3339),
			})
		}
	}
	keys := make([]string, 0, len(subjects))
	for key := range subjects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		graph.Subjects = append(graph.Subjects, *subjects[key])
	}
	graph.SubjectsMatched = len(graph.Subjects)
	if graph.SubjectsMatched > 0 {
		graph.Status = "matches_observed"
	}
	return graph
}

func unavailableTransactionGuardActorMemoryGraph(graph transactionGuardActorMemoryGraph, reason string) transactionGuardActorMemoryGraph {
	graph.Status = "source_unavailable"
	graph.Complete = false
	graph.Limitations = append(graph.Limitations, strings.TrimSpace(reason), "Actor-memory unavailability does not imply safety or risk.")
	graph.EvidenceHashSHA256 = transactionGuardActorMemoryGraphHash(graph)
	return graph
}

func appendUniqueSortedString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	values = append(values, value)
	sort.Strings(values)
	return values
}

func transactionGuardActorMemoryGraphHash(graph transactionGuardActorMemoryGraph) string {
	graph.EvidenceHashSHA256 = ""
	payload, err := json.Marshal(graph)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}
