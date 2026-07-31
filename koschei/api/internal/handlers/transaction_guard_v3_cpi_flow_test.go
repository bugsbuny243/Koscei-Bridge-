package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"koschei/api/internal/services"
)

func TestAnalyzeTransactionGuardV3CPIFlowDetectsUndeclaredWalletExitAndVault(t *testing.T) {
	wallet := guardV3TestAddress(2)
	source := guardV3TestAddress(3)
	mint := guardV3TestAddress(4)
	destination := guardV3TestAddress(5)
	controller := guardV3TestAddress(6)
	parentProgram := guardV3TestAddress(7)

	decoded := transactionGuardDecodedTransaction{
		Available: true,
		Complete:  true,
		StaticAccounts: []transactionGuardDecodedAccount{
			{Index: 0, Address: source, Writable: true, Source: "static"},
			{Index: 1, Address: mint, Source: "static"},
			{Index: 2, Address: destination, Writable: true, Source: "static"},
			{Index: 3, Address: wallet, Signer: true, Writable: true, Source: "static"},
			{Index: 4, Address: guardV3SPLTokenProgramID, Source: "static"},
			{Index: 5, Address: parentProgram, Source: "static"},
			{Index: 6, Address: controller, Source: "static"},
		},
		Instructions: []transactionGuardDecodedInstruction{{Index: 0, ProgramID: parentProgram, ProgramResolved: true}},
	}
	data := make([]byte, 10)
	data[0] = 12
	binary.LittleEndian.PutUint64(data[1:9], 500)
	data[9] = 2
	groups := []services.SolanaInnerInstructionGroup{{
		Index: 0,
		Instructions: []services.SolanaInnerInstruction{{
			ProgramIDIndex: 4,
			Accounts:       []int{0, 1, 2, 3, 6},
			Data:           guardV3Base58Encode(data),
		}},
	}}
	preOrder := []string{source, destination, controller}
	postOrder := append([]string{}, preOrder...)
	pre := []*services.SolanaAccountInfo{
		guardV3TestTokenAccountInfo(t, mint, wallet, 1000),
		guardV3TestTokenAccountInfo(t, mint, controller, 0),
		{Owner: parentProgram, Executable: false, Data: []string{base64.StdEncoding.EncodeToString(make([]byte, 8)), "base64"}},
	}
	post := []*services.SolanaAccountInfo{
		guardV3TestTokenAccountInfo(t, mint, wallet, 500),
		guardV3TestTokenAccountInfo(t, mint, controller, 500),
		pre[2],
	}
	policy := []transactionGuardAccount{{Address: source, Role: "input"}}

	flow, findings := analyzeTransactionGuardV3CPIFlow(decoded, wallet, policy, groups, preOrder, postOrder, pre, post)
	if !flow.Available || !flow.Complete || flow.Status != "complete" {
		t.Fatalf("flow=%#v", flow)
	}
	if flow.InnerInstructionCount != 1 || len(flow.AssetMovements) != 1 {
		t.Fatalf("inner=%d movements=%#v", flow.InnerInstructionCount, flow.AssetMovements)
	}
	movement := flow.AssetMovements[0]
	if !movement.WalletOrigin || !movement.UndeclaredByAccountPolicy || movement.Destination != destination || movement.Mint != mint {
		t.Fatalf("movement=%#v", movement)
	}
	if flow.UndeclaredMovementCount != 1 || !hasFindingPrefix(findings, "cpi_undeclared_wallet_exit_") {
		t.Fatalf("flow=%#v findings=%#v", flow, findings)
	}
	vaultFound := false
	for _, account := range flow.Accounts {
		if account.Address == destination && account.VaultCandidate && account.Controller == controller && account.ControllerProgramOwner == parentProgram {
			vaultFound = true
		}
	}
	if !vaultFound {
		t.Fatalf("accounts=%#v", flow.Accounts)
	}

	refined, refinedFindings := refineTransactionGuardV3CPIProgramPolicy(flow, findings, []string{parentProgram}, nil)
	if !refined.Complete || refined.UndeclaredMovementCount != 0 || refined.AssetMovements[0].UndeclaredByAccountPolicy {
		t.Fatalf("refined=%#v", refined)
	}
	if hasFindingPrefix(refinedFindings, "cpi_undeclared_wallet_exit_") {
		t.Fatalf("verified expected-program vault must not be called an undeclared exit: %#v", refinedFindings)
	}
}

func TestAnalyzeTransactionGuardV3CPIFlowDoesNotCallUnspecifiedPolicyUndeclared(t *testing.T) {
	wallet := guardV3TestAddress(8)
	destination := guardV3TestAddress(9)
	parentProgram := guardV3TestAddress(10)
	decoded := transactionGuardDecodedTransaction{
		Available: true,
		Complete:  true,
		StaticAccounts: []transactionGuardDecodedAccount{
			{Index: 0, Address: wallet, Signer: true, Writable: true},
			{Index: 1, Address: destination, Writable: true},
			{Index: 2, Address: guardV3SystemProgramID},
		},
		Instructions: []transactionGuardDecodedInstruction{{Index: 0, ProgramID: parentProgram, ProgramResolved: true}},
	}
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[:4], 2)
	binary.LittleEndian.PutUint64(data[4:], 1_000_000)
	groups := []services.SolanaInnerInstructionGroup{{Index: 0, Instructions: []services.SolanaInnerInstruction{{ProgramIDIndex: 2, Accounts: []int{0, 1}, Data: guardV3Base58Encode(data)}}}}

	flow, findings := analyzeTransactionGuardV3CPIFlow(decoded, wallet, nil, groups, nil, nil, nil, nil)
	if !flow.Complete || len(flow.AssetMovements) != 1 || !flow.AssetMovements[0].WalletOrigin {
		t.Fatalf("flow=%#v", flow)
	}
	if flow.AssetMovements[0].PolicyCompared || flow.AssetMovements[0].UndeclaredByAccountPolicy || flow.UndeclaredMovementCount != 0 {
		t.Fatalf("movement=%#v flow=%#v", flow.AssetMovements[0], flow)
	}
	if hasFindingPrefix(findings, "cpi_undeclared_wallet_exit_") {
		t.Fatalf("findings=%#v", findings)
	}
}

func TestRefineTransactionGuardV3CPIProgramPolicyWithholdsUnverifiedIntermediary(t *testing.T) {
	wallet := guardV3TestAddress(11)
	destination := guardV3TestAddress(12)
	parentProgram := guardV3TestAddress(13)
	flow := transactionGuardCPIFlowAnalysis{
		Available: true, Complete: true, Status: "complete", UndeclaredMovementCount: 1,
		AssetMovements: []transactionGuardCPIAssetMovement{{
			AssetType: "token", Destination: destination, ParentProgramID: parentProgram,
			WalletOrigin: true, PolicyCompared: true, UndeclaredByAccountPolicy: true,
		}},
		Accounts: []transactionGuardCPIAccount{{
			Address: destination, Classification: "token_account", TokenOwner: wallet,
			ControlStatus: "external_token_controller", ControllerProgramOwner: "",
		}},
	}
	findings := []transactionFirewallFinding{{
		Code: "cpi_undeclared_wallet_exit_" + guardV3CompactAddressHash(destination), Severity: "high", Score: 50,
	}}

	refined, refinedFindings := refineTransactionGuardV3CPIProgramPolicy(flow, findings, []string{parentProgram}, nil)
	if refined.Complete || refined.Status != "protocol_intermediary_unverified" || refined.UndeclaredMovementCount != 0 {
		t.Fatalf("refined=%#v", refined)
	}
	if hasFindingPrefix(refinedFindings, "cpi_undeclared_wallet_exit_") || !hasFindingPrefix(refinedFindings, "cpi_protocol_intermediary_unverified_") {
		t.Fatalf("findings=%#v", refinedFindings)
	}
}

func TestTransactionGuardV3ThreatDecodedWithCPIAddsInnerSubjects(t *testing.T) {
	destination := guardV3TestAddress(14)
	program := guardV3TestAddress(15)
	flow := transactionGuardCPIFlowAnalysis{
		ProgramIDs: []string{program},
		AssetMovements: []transactionGuardCPIAssetMovement{{
			AssetType: "SOL", Kind: "transfer", Source: guardV3TestAddress(16), Destination: destination, AmountRaw: "1",
		}},
	}
	got := transactionGuardV3ThreatDecodedWithCPI(transactionGuardDecodedTransaction{}, flow, "")
	if len(got.ProgramIDs) != 1 || got.ProgramIDs[0] != program || len(got.SOLTransfers) != 1 || got.SOLTransfers[0].Recipient != destination {
		t.Fatalf("decoded=%#v", got)
	}
}

func guardV3TestAddress(marker byte) string {
	return guardV3Base58Encode(bytes.Repeat([]byte{marker}, 32))
}

func guardV3TestTokenAccountInfo(t *testing.T, mint, owner string, amount uint64) *services.SolanaAccountInfo {
	t.Helper()
	mintBytes, err := decodeSolanaPublicKey(mint)
	if err != nil {
		t.Fatal(err)
	}
	ownerBytes, err := decodeSolanaPublicKey(owner)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 165)
	copy(data[:32], mintBytes)
	copy(data[32:64], ownerBytes)
	binary.LittleEndian.PutUint64(data[64:72], amount)
	return &services.SolanaAccountInfo{
		Owner: guardV3SPLTokenProgramID,
		Data:  []string{base64.StdEncoding.EncodeToString(data), "base64"},
	}
}

func hasFindingPrefix(findings []transactionFirewallFinding, prefix string) bool {
	for _, finding := range findings {
		if strings.HasPrefix(finding.Code, prefix) {
			return true
		}
	}
	return false
}
