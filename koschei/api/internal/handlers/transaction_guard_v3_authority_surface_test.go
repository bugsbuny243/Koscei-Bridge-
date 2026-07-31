package handlers

import (
	"encoding/base64"
	"encoding/binary"
	"math"
	"testing"

	"koschei/api/internal/services"
)

func TestDecodeSetAuthorityUsesOneByteOptionalPubkey(t *testing.T) {
	account := guardV3TestAddress(21)
	current := guardV3TestAddress(22)
	newAuthority := guardV3TestAddress(23)
	newBytes, err := decodeSolanaPublicKey(newAuthority)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte{6, 8, 1}
	data = append(data, newBytes...)

	event, relevant, err := decodeTransactionGuardV3AuthorityEvent(transactionGuardAuthorityInstruction{
		Source: "outer", ProgramID: guardV3Token2022ProgramID,
		Accounts: []string{account, current}, Data: data,
	})
	if err != nil || !relevant {
		t.Fatalf("relevant=%v err=%v", relevant, err)
	}
	if event.AuthorityTypeName != "permanent_delegate" || event.NewAuthority != newAuthority || !event.MintWide || !event.CanTransfer || !event.CanBurn {
		t.Fatalf("event=%#v", event)
	}
}

func TestAnalyzeAuthoritySurfacePermanentDelegateBlocks(t *testing.T) {
	mint := guardV3TestAddress(24)
	delegate := guardV3TestAddress(25)
	delegateBytes, _ := decodeSolanaPublicKey(delegate)
	data := append([]byte{35}, delegateBytes...)
	decoded := guardV3AuthorityTestDecoded(guardV3Token2022ProgramID, []string{mint}, data)

	analysis, findings := analyzeTransactionGuardV3AuthoritySurface(decoded, nil, transactionGuardAuthoritySnapshots{})
	if !analysis.Complete || analysis.EventCount != 1 || analysis.MintWideEventCount != 1 {
		t.Fatalf("analysis=%#v", analysis)
	}
	event := analysis.Events[0]
	if event.Kind != "initialize_permanent_delegate" || event.Delegate != delegate || !event.Persistent || !event.CanTransfer || !event.CanBurn {
		t.Fatalf("event=%#v", event)
	}
	if !hasFindingPrefix(findings, "authority_permanent_delegate_") || findings[0].Score != 75 {
		t.Fatalf("findings=%#v", findings)
	}
}

func TestAnalyzeAuthoritySurfaceTransferFeeAndHook(t *testing.T) {
	mint := guardV3TestAddress(26)
	feeAuthority := guardV3TestAddress(27)
	withdrawAuthority := guardV3TestAddress(28)
	hookAuthority := guardV3TestAddress(29)
	hookProgram := guardV3TestAddress(30)
	feeAuthorityBytes, _ := decodeSolanaPublicKey(feeAuthority)
	withdrawBytes, _ := decodeSolanaPublicKey(withdrawAuthority)
	hookAuthorityBytes, _ := decodeSolanaPublicKey(hookAuthority)
	hookProgramBytes, _ := decodeSolanaPublicKey(hookProgram)

	feeData := []byte{26, 0, 1}
	feeData = append(feeData, feeAuthorityBytes...)
	feeData = append(feeData, 1)
	feeData = append(feeData, withdrawBytes...)
	feeData = append(feeData, 0xB0, 0x04) // 1200 bps
	maximum := make([]byte, 8)
	binary.LittleEndian.PutUint64(maximum, 5000)
	feeData = append(feeData, maximum...)

	hookData := []byte{36, 0}
	hookData = append(hookData, hookAuthorityBytes...)
	hookData = append(hookData, hookProgramBytes...)

	decoded := transactionGuardDecodedTransaction{
		Available: true, Complete: true,
		StaticAccounts: []transactionGuardDecodedAccount{
			{Index: 0, Address: mint}, {Index: 1, Address: guardV3Token2022ProgramID},
		},
		parsedInstructions: []guardV3ParsedInstruction{
			{ProgramIndex: 1, AccountIndexes: []int{0}, Data: feeData},
			{ProgramIndex: 1, AccountIndexes: []int{0}, Data: hookData},
		},
	}
	analysis, findings := analyzeTransactionGuardV3AuthoritySurface(decoded, nil, transactionGuardAuthoritySnapshots{})
	if analysis.EventCount != 2 || len(analysis.TransferHookProgramIDs) != 1 || analysis.TransferHookProgramIDs[0] != hookProgram {
		t.Fatalf("analysis=%#v", analysis)
	}
	if !hasFindingPrefix(findings, "authority_transfer_fee_") || !hasFindingPrefix(findings, "authority_transfer_hook_") {
		t.Fatalf("findings=%#v", findings)
	}
}

func TestApproveFinalStateReportsRemainingDelegate(t *testing.T) {
	source := guardV3TestAddress(31)
	mint := guardV3TestAddress(32)
	owner := guardV3TestAddress(33)
	delegate := guardV3TestAddress(34)
	data := make([]byte, 10)
	data[0] = 13
	binary.LittleEndian.PutUint64(data[1:9], math.MaxUint64)
	data[9] = 6
	decoded := guardV3AuthorityTestDecoded(guardV3SPLTokenProgramID, []string{source, mint, delegate, owner}, data)
	postInfo := guardV3AuthorityTokenInfo(t, mint, owner, delegate, 900)
	snapshots := transactionGuardAuthoritySnapshots{
		PostOrder: []string{source}, Post: []*services.SolanaAccountInfo{postInfo},
	}

	analysis, findings := analyzeTransactionGuardV3AuthoritySurface(decoded, nil, snapshots)
	if analysis.ActiveDelegateCount != 1 || len(analysis.Events) != 1 {
		t.Fatalf("analysis=%#v", analysis)
	}
	event := analysis.Events[0]
	if event.ActiveAfterSimulation == nil || !*event.ActiveAfterSimulation || event.PostDelegate != delegate || event.PostDelegatedAmountRaw != "900" || !event.EffectivelyUnlimited {
		t.Fatalf("event=%#v", event)
	}
	if !hasFindingPrefix(findings, "authority_delegate_approval_") || findings[0].Score != 35 {
		t.Fatalf("findings=%#v", findings)
	}
}

func guardV3AuthorityTestDecoded(program string, accounts []string, data []byte) transactionGuardDecodedTransaction {
	static := make([]transactionGuardDecodedAccount, 0, len(accounts)+1)
	indexes := make([]int, 0, len(accounts))
	for index, address := range accounts {
		static = append(static, transactionGuardDecodedAccount{Index: index, Address: address})
		indexes = append(indexes, index)
	}
	static = append(static, transactionGuardDecodedAccount{Index: len(accounts), Address: program})
	return transactionGuardDecodedTransaction{
		Available: true, Complete: true, StaticAccounts: static,
		parsedInstructions: []guardV3ParsedInstruction{{ProgramIndex: len(accounts), AccountIndexes: indexes, Data: data}},
	}
}

func guardV3AuthorityTokenInfo(t *testing.T, mint, owner, delegate string, delegatedAmount uint64) *services.SolanaAccountInfo {
	t.Helper()
	mintBytes, err := decodeSolanaPublicKey(mint)
	if err != nil {
		t.Fatal(err)
	}
	ownerBytes, err := decodeSolanaPublicKey(owner)
	if err != nil {
		t.Fatal(err)
	}
	delegateBytes, err := decodeSolanaPublicKey(delegate)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 165)
	copy(data[:32], mintBytes)
	copy(data[32:64], ownerBytes)
	binary.LittleEndian.PutUint32(data[72:76], 1)
	copy(data[76:108], delegateBytes)
	data[108] = 1
	binary.LittleEndian.PutUint64(data[121:129], delegatedAmount)
	return &services.SolanaAccountInfo{
		Owner: guardV3SPLTokenProgramID,
		Data: []string{base64.StdEncoding.EncodeToString(data), "base64"},
	}
}
