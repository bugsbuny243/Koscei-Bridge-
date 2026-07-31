package handlers

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"koschei/api/internal/services"
)

func TestAnalyzeTransactionGuardV3CPIFlowDetectsUndeclaredWalletExitAndVault(t *testing.T) {
	wallet := "22222222222222222222222222222222"
	source := "33333333333333333333333333333333"
	mint := "44444444444444444444444444444444"
	destination := "55555555555555555555555555555555"
	controller := "66666666666666666666666666666666"
	parentProgram := "77777777777777777777777777777777"

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
			{Index: 6, Address: controller, Writable: true, Source: "static"},
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
		if account.Address == destination && account.VaultCandidate && account.Controller == controller {
			vaultFound = true
		}
	}
	if !vaultFound {
		t.Fatalf("accounts=%#v", flow.Accounts)
	}
}

func TestAnalyzeTransactionGuardV3CPIFlowDoesNotCallUnspecifiedPolicyUndeclared(t *testing.T) {
	wallet := "22222222222222222222222222222222"
	destination := "33333333333333333333333333333333"
	decoded := transactionGuardDecodedTransaction{
		Available: true,
		Complete:  true,
		StaticAccounts: []transactionGuardDecodedAccount{
			{Index: 0, Address: wallet, Signer: true, Writable: true},
			{Index: 1, Address: destination, Writable: true},
			{Index: 2, Address: guardV3SystemProgramID},
		},
		Instructions: []transactionGuardDecodedInstruction{{Index: 0, ProgramID: "44444444444444444444444444444444", ProgramResolved: true}},
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

func TestTransactionGuardV3ThreatDecodedWithCPIAddsInnerSubjects(t *testing.T) {
	destination := "33333333333333333333333333333333"
	program := "44444444444444444444444444444444"
	flow := transactionGuardCPIFlowAnalysis{
		ProgramIDs: []string{program},
		AssetMovements: []transactionGuardCPIAssetMovement{{
			AssetType: "SOL", Kind: "transfer", Source: "22222222222222222222222222222222", Destination: destination, AmountRaw: "1",
		}},
	}
	got := transactionGuardV3ThreatDecodedWithCPI(transactionGuardDecodedTransaction{}, flow, "")
	if len(got.ProgramIDs) != 1 || got.ProgramIDs[0] != program || len(got.SOLTransfers) != 1 || got.SOLTransfers[0].Recipient != destination {
		t.Fatalf("decoded=%#v", got)
	}
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
