package handlers

import (
	"testing"

	"koschei/api/internal/defense"
)

func TestBuildTransactionGuardProgramTrustGraphDeterministicAndEvidenceOnly(t *testing.T) {
	observed := map[string][]string{
		guardV3SystemProgramID:    {"outer_instruction"},
		guardV3SPLTokenProgramID:  {"cpi", "outer_instruction"},
		guardV3Token2022ProgramID: {"transfer_hook"},
	}
	snapshots := map[string]defense.DeploymentSnapshot{
		guardV3SPLTokenProgramID: {
			SnapshotRef:          "KDS1-0123456789abcdef0123456789abcdef",
			ProgramID:            guardV3SPLTokenProgramID,
			Network:              "solana-mainnet",
			LoaderKind:           "bpf_upgradeable_loader",
			ProgramDataAddress:   "TokenProgramDataFixture",
			AccountSlot:          900,
			DeploymentSlot:       800,
			UpgradeAuthority:     "UpgradeAuthorityFixture",
			UpgradeAuthorityOpen: true,
			Executable:           true,
			CanonicalBinaryHash:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			SourceCommit:         "deadbeef",
			MatchStatus:          "matched_full_binary",
			MatchEvidenceStatus:  "observed",
			SnapshotHash:         "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			VerdictAuthority:     false,
		},
	}

	first := buildTransactionGuardProgramTrustGraph(observed, snapshots, "")
	second := buildTransactionGuardProgramTrustGraph(map[string][]string{
		guardV3Token2022ProgramID: {"transfer_hook"},
		guardV3SPLTokenProgramID:  {"cpi", "outer_instruction"},
		guardV3SystemProgramID:    {"outer_instruction"},
	}, snapshots, "")
	if first.EvidenceHashSHA256 == "" || first.EvidenceHashSHA256 != second.EvidenceHashSHA256 {
		t.Fatalf("hashes first=%q second=%q", first.EvidenceHashSHA256, second.EvidenceHashSHA256)
	}
	if first.Complete || first.Status != "partial" || first.SnapshotCount != 1 || first.MissingSnapshotCount != 1 || first.BuiltinCount != 1 {
		t.Fatalf("graph=%#v", first)
	}
	if first.VerdictAuthority {
		t.Fatal("Program Trust Graph unexpectedly received verdict authority")
	}

	var linked transactionGuardProgramTrustNode
	for _, node := range first.Programs {
		if node.ProgramID == guardV3SPLTokenProgramID {
			linked = node
		}
	}
	if !linked.DefenseSnapshotLinked || !linked.SourceMatched || !linked.UpgradeAuthorityOpen || linked.CanonicalBinaryHash == "" {
		t.Fatalf("linked node=%#v", linked)
	}
}

func TestBuildTransactionGuardProgramTrustGraphRejectsInvalidProgramIdentity(t *testing.T) {
	graph := buildTransactionGuardProgramTrustGraph(map[string][]string{
		"unresolved-program:7": {"cpi"},
	}, nil, "deployment_snapshot_database_unavailable")
	if graph.Complete || graph.Status != "partial" || graph.InvalidProgramCount != 1 {
		t.Fatalf("graph=%#v", graph)
	}
	if len(graph.Programs) != 1 || graph.Programs[0].TrustStatus != "invalid_program_id" {
		t.Fatalf("programs=%#v", graph.Programs)
	}
}

func TestTransactionGuardProgramTrustObservationsPreserveSources(t *testing.T) {
	observed := transactionGuardProgramTrustObservations(
		transactionGuardDecodedTransaction{ProgramIDs: []string{guardV3SPLTokenProgramID}},
		transactionGuardCPIFlowAnalysis{ProgramIDs: []string{guardV3SPLTokenProgramID, guardV3Token2022ProgramID}},
		transactionGuardAuthoritySurfaceAnalysis{TransferHookProgramIDs: []string{guardV3Token2022ProgramID}},
	)
	if got := observed[guardV3SPLTokenProgramID]; len(got) != 2 || got[0] != "cpi" || got[1] != "outer_instruction" {
		t.Fatalf("spl sources=%v", got)
	}
	if got := observed[guardV3Token2022ProgramID]; len(got) != 2 || got[0] != "cpi" || got[1] != "transfer_hook" {
		t.Fatalf("token2022 sources=%v", got)
	}
}
