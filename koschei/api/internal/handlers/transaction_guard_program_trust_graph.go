package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"koschei/api/internal/defense"
)

const transactionGuardProgramTrustGraphVersion = "koschei-program-trust-graph-v1"

type transactionGuardProgramTrustNode struct {
	ProgramID             string   `json:"program_id"`
	ObservedIn            []string `json:"observed_in"`
	TrustStatus           string   `json:"trust_status"`
	BuiltinName           string   `json:"builtin_name,omitempty"`
	SnapshotRef           string   `json:"snapshot_ref,omitempty"`
	SnapshotHash          string   `json:"snapshot_hash,omitempty"`
	LoaderKind            string   `json:"loader_kind,omitempty"`
	ProgramDataAddress    string   `json:"programdata_address,omitempty"`
	AccountSlot           uint64   `json:"account_slot,omitempty"`
	DeploymentSlot        uint64   `json:"deployment_slot,omitempty"`
	UpgradeAuthority      string   `json:"upgrade_authority,omitempty"`
	UpgradeAuthorityOpen  bool     `json:"upgrade_authority_open"`
	Executable            bool     `json:"executable"`
	CanonicalBinaryHash   string   `json:"canonical_binary_hash,omitempty"`
	SourceCommit          string   `json:"source_commit,omitempty"`
	MatchStatus           string   `json:"source_match_status,omitempty"`
	MatchEvidenceStatus   string   `json:"source_match_evidence_status,omitempty"`
	SourceMatched         bool     `json:"source_matched"`
	DefenseSnapshotLinked bool     `json:"defense_snapshot_linked"`
}

type transactionGuardProgramTrustGraph struct {
	Version              string                             `json:"version"`
	Status               string                             `json:"status"`
	Complete             bool                               `json:"complete"`
	ProgramCount         int                                `json:"program_count"`
	BuiltinCount         int                                `json:"builtin_count"`
	SnapshotCount        int                                `json:"defense_snapshot_count"`
	MissingSnapshotCount int                                `json:"missing_snapshot_count"`
	InvalidProgramCount  int                                `json:"invalid_program_count"`
	Programs             []transactionGuardProgramTrustNode `json:"programs"`
	Limitations          []string                           `json:"limitations"`
	EvidenceHashSHA256   string                             `json:"evidence_hash_sha256"`
	VerdictAuthority     bool                               `json:"verdict_authority"`
}

func (h *Handler) collectTransactionGuardProgramTrustGraph(ctx context.Context, network string, decoded transactionGuardDecodedTransaction, cpi transactionGuardCPIFlowAnalysis, authority transactionGuardAuthoritySurfaceAnalysis) transactionGuardProgramTrustGraph {
	observed := transactionGuardProgramTrustObservations(decoded, cpi, authority)
	programIDs := make([]string, 0, len(observed))
	for programID := range observed {
		programIDs = append(programIDs, programID)
	}
	sort.Strings(programIDs)
	if len(programIDs) == 0 {
		return buildTransactionGuardProgramTrustGraph(observed, nil, "")
	}

	var db = h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return buildTransactionGuardProgramTrustGraph(observed, nil, "deployment_snapshot_database_unavailable")
	}
	snapshots, err := defense.LatestDeploymentSnapshots(ctx, db, network, programIDs)
	if err != nil {
		return buildTransactionGuardProgramTrustGraph(observed, nil, "deployment_snapshot_lookup_unavailable")
	}
	return buildTransactionGuardProgramTrustGraph(observed, snapshots, "")
}

func transactionGuardProgramTrustObservations(decoded transactionGuardDecodedTransaction, cpi transactionGuardCPIFlowAnalysis, authority transactionGuardAuthoritySurfaceAnalysis) map[string][]string {
	type sourceSet map[string]struct{}
	observed := map[string]sourceSet{}
	add := func(source string, programIDs []string) {
		for _, raw := range programIDs {
			programID := strings.TrimSpace(raw)
			if programID == "" {
				continue
			}
			if observed[programID] == nil {
				observed[programID] = sourceSet{}
			}
			observed[programID][source] = struct{}{}
		}
	}
	add("outer_instruction", decoded.ProgramIDs)
	add("cpi", cpi.ProgramIDs)
	add("transfer_hook", authority.TransferHookProgramIDs)

	out := make(map[string][]string, len(observed))
	for programID, sources := range observed {
		values := make([]string, 0, len(sources))
		for source := range sources {
			values = append(values, source)
		}
		sort.Strings(values)
		out[programID] = values
	}
	return out
}

func buildTransactionGuardProgramTrustGraph(observed map[string][]string, snapshots map[string]defense.DeploymentSnapshot, lookupLimitation string) transactionGuardProgramTrustGraph {
	graph := transactionGuardProgramTrustGraph{
		Version:          transactionGuardProgramTrustGraphVersion,
		Status:           "complete",
		Complete:         true,
		Programs:         []transactionGuardProgramTrustNode{},
		Limitations:      []string{},
		VerdictAuthority: false,
	}
	programIDs := make([]string, 0, len(observed))
	for programID := range observed {
		programIDs = append(programIDs, programID)
	}
	sort.Strings(programIDs)
	graph.ProgramCount = len(programIDs)
	if len(programIDs) == 0 {
		graph.Status = "no_programs_observed"
		graph.EvidenceHashSHA256 = transactionGuardProgramTrustGraphHash(graph)
		return graph
	}

	for _, programID := range programIDs {
		node := transactionGuardProgramTrustNode{
			ProgramID:  programID,
			ObservedIn: append([]string(nil), observed[programID]...),
			TrustStatus: "snapshot_unavailable",
		}
		if !isValidSolanaAddress(programID) {
			node.TrustStatus = "invalid_program_id"
			graph.InvalidProgramCount++
			graph.Complete = false
			graph.Programs = append(graph.Programs, node)
			continue
		}
		if builtinName, builtin := transactionGuardProgramTrustBuiltin(programID); builtin {
			node.TrustStatus = "builtin_not_applicable"
			node.BuiltinName = builtinName
			node.Executable = true
			graph.BuiltinCount++
			graph.Programs = append(graph.Programs, node)
			continue
		}
		snapshot, ok := snapshots[programID]
		if !ok {
			graph.MissingSnapshotCount++
			graph.Complete = false
			graph.Programs = append(graph.Programs, node)
			continue
		}
		node.TrustStatus = "defense_snapshot_observed"
		node.SnapshotRef = strings.TrimSpace(snapshot.SnapshotRef)
		node.SnapshotHash = strings.TrimSpace(snapshot.SnapshotHash)
		node.LoaderKind = strings.TrimSpace(snapshot.LoaderKind)
		node.ProgramDataAddress = strings.TrimSpace(snapshot.ProgramDataAddress)
		node.AccountSlot = snapshot.AccountSlot
		node.DeploymentSlot = snapshot.DeploymentSlot
		node.UpgradeAuthority = strings.TrimSpace(snapshot.UpgradeAuthority)
		node.UpgradeAuthorityOpen = snapshot.UpgradeAuthorityOpen
		node.Executable = snapshot.Executable
		node.CanonicalBinaryHash = strings.TrimSpace(snapshot.CanonicalBinaryHash)
		node.SourceCommit = strings.TrimSpace(snapshot.SourceCommit)
		node.MatchStatus = strings.TrimSpace(snapshot.MatchStatus)
		node.MatchEvidenceStatus = strings.TrimSpace(snapshot.MatchEvidenceStatus)
		node.SourceMatched = transactionGuardProgramTrustSourceMatched(snapshot.MatchStatus)
		node.DefenseSnapshotLinked = true
		graph.SnapshotCount++
		graph.Programs = append(graph.Programs, node)
	}

	if strings.TrimSpace(lookupLimitation) != "" {
		graph.Limitations = append(graph.Limitations, strings.TrimSpace(lookupLimitation))
		graph.Complete = false
	}
	if graph.MissingSnapshotCount > 0 {
		graph.Limitations = append(graph.Limitations, "One or more invoked non-builtin programs have no persisted Defense OS deployment snapshot; no source or bytecode provenance is inferred for them.")
	}
	if graph.InvalidProgramCount > 0 {
		graph.Limitations = append(graph.Limitations, "One or more observed program identifiers were not valid Solana public keys and were excluded from Defense OS provenance claims.")
	}
	if !graph.Complete {
		graph.Status = "partial"
	}
	graph.EvidenceHashSHA256 = transactionGuardProgramTrustGraphHash(graph)
	return graph
}

func transactionGuardProgramTrustBuiltin(programID string) (string, bool) {
	switch strings.TrimSpace(programID) {
	case guardV3SystemProgramID:
		return "system_program", true
	case guardV3AddressLookupTableProgramID:
		return "address_lookup_table_program", true
	case "ComputeBudget111111111111111111111111111111":
		return "compute_budget_program", true
	default:
		return "", false
	}
}

func transactionGuardProgramTrustSourceMatched(status string) bool {
	switch strings.TrimSpace(status) {
	case "matched_full_binary", "matched_after_zero_padding_normalization":
		return true
	default:
		return false
	}
}

func transactionGuardProgramTrustGraphHash(graph transactionGuardProgramTrustGraph) string {
	graph.EvidenceHashSHA256 = ""
	payload, err := json.Marshal(graph)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}
