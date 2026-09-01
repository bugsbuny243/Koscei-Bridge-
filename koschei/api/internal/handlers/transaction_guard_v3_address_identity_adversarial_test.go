package handlers

import (
	"strings"
	"testing"

	"koschei/api/internal/services"
)

const (
	guardCaseVariantAddressA = "AbCDefGHjkMNpQRstUVwxYZ123456789"
	guardCaseVariantAddressB = "aBcdefghJKmnPqrSTuvWXyz123456789"
)

func TestTransactionGuardV3AddressWritableDoesNotCaseFoldSolanaIdentity(t *testing.T) {
	if guardCaseVariantAddressA == guardCaseVariantAddressB || !strings.EqualFold(guardCaseVariantAddressA, guardCaseVariantAddressB) {
		t.Fatal("case-variant fixtures must be exact-distinct and collide under EqualFold")
	}
	decoded := transactionGuardDecodedTransaction{
		StaticAccounts: []transactionGuardDecodedAccount{
			{Address: guardCaseVariantAddressA, Writable: true},
			{Address: guardCaseVariantAddressB, Writable: false},
		},
	}
	if !transactionGuardV3AddressWritable(decoded, guardCaseVariantAddressA) {
		t.Fatal("exact writable address was not recognized")
	}
	if transactionGuardV3AddressWritable(decoded, guardCaseVariantAddressB) {
		t.Fatal("case-variant Solana address inherited another account's writable flag")
	}
}

func TestTransactionGuardV3WalletDeltaDoesNotCaseFoldSolanaIdentity(t *testing.T) {
	decoded := transactionGuardDecodedTransaction{
		Available: true,
		Complete:  true,
		StaticAccounts: []transactionGuardDecodedAccount{
			{Address: guardCaseVariantAddressA, Writable: true},
		},
	}
	addresses := []string{guardCaseVariantAddressA}
	pre := []*services.SolanaAccountInfo{{Owner: guardV3SystemProgramID, Lamports: 10}}
	post := []*services.SolanaAccountInfo{{Owner: guardV3SystemProgramID, Lamports: 20}}

	analysis, findings := evaluateTransactionGuardV3AutomaticBalances(
		decoded,
		guardCaseVariantAddressB,
		addresses,
		1,
		true,
		addresses,
		addresses,
		pre,
		post,
	)
	if !analysis.Complete {
		t.Fatalf("exact account evidence unexpectedly incomplete: %#v", analysis)
	}
	if analysis.WalletSOLDeltaLamports != "0" || analysis.WalletSOLSpentLamports != "0" || analysis.WalletSOLReceivedLamports != "0" {
		t.Fatalf("case-variant account delta was misattributed to wallet: %#v", analysis)
	}
	if guardV3TestHasFinding(findings, "automatic_wallet_sol_delta") {
		t.Fatalf("case-variant account emitted a wallet delta finding: %#v", findings)
	}
}

func TestTransactionGuardV3ProgramOwnerMutationDoesNotCaseFoldSolanaIdentity(t *testing.T) {
	address := guardV3TestAddress(90)
	decoded := transactionGuardDecodedTransaction{
		Available: true,
		Complete:  true,
		StaticAccounts: []transactionGuardDecodedAccount{
			{Address: address, Writable: true},
		},
	}
	addresses := []string{address}
	pre := []*services.SolanaAccountInfo{{Owner: guardCaseVariantAddressA, Lamports: 100}}
	post := []*services.SolanaAccountInfo{{Owner: guardCaseVariantAddressB, Lamports: 100}}

	analysis, findings := evaluateTransactionGuardV3AutomaticBalances(
		decoded,
		"",
		addresses,
		1,
		true,
		addresses,
		addresses,
		pre,
		post,
	)
	if !analysis.Complete || len(analysis.Accounts) != 1 {
		t.Fatalf("owner-mutation evidence unexpectedly incomplete: %#v", analysis)
	}
	if !analysis.Accounts[0].Changed || analysis.ChangedAccountCount != 1 {
		t.Fatalf("case-variant program owner mutation was hidden: %#v", analysis.Accounts)
	}
	if !guardV3TestHasFinding(findings, "automatic_account_program_owner_changed") {
		t.Fatalf("program-owner mutation finding missing: %#v", findings)
	}
}
