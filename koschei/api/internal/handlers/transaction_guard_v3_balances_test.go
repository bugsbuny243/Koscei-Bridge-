package handlers

import (
	"encoding/base64"
	"encoding/binary"
	"testing"

	"koschei/api/internal/services"
)

func TestEvaluateTransactionGuardV3AutomaticBalancesTracksSOLAndToken(t *testing.T) {
	wallet := guardV3Base58Encode(guardV3TestKey(20))
	tokenAccount := guardV3Base58Encode(guardV3TestKey(21))
	mint := guardV3TestKey(22)
	owner := guardV3TestKey(20)
	decoded := transactionGuardDecodedTransaction{
		Available: true, Complete: true,
		StaticAccounts: []transactionGuardDecodedAccount{
			{Address: wallet, Writable: true},
			{Address: tokenAccount, Writable: true},
		},
	}
	pre := []*services.SolanaAccountInfo{
		{Owner: guardV3SystemProgramID, Lamports: 5_000_000},
		guardV3AutomaticTokenAccountInfo(mint, owner, 100, 2_039_280),
	}
	post := []*services.SolanaAccountInfo{
		{Owner: guardV3SystemProgramID, Lamports: 3_000_000},
		guardV3AutomaticTokenAccountInfo(mint, owner, 20, 2_039_280),
	}
	addresses := []string{wallet, tokenAccount}
	analysis, findings := evaluateTransactionGuardV3AutomaticBalances(decoded, wallet, addresses, len(addresses), true, addresses, addresses, pre, post)
	if !analysis.Available || !analysis.Complete || analysis.Status != "verified_rpc_simulation_balance_changes" {
		t.Fatalf("unexpected balance analysis: %+v", analysis)
	}
	if analysis.WalletSOLDeltaLamports != "-2000000" || analysis.WalletSOLSpentLamports != "2000000" {
		t.Fatalf("unexpected wallet SOL delta: %+v", analysis)
	}
	if analysis.TokenAccountChangeCount != 1 || len(analysis.Accounts) != 2 || analysis.Accounts[1].TokenDeltaRaw != "-80" {
		t.Fatalf("unexpected token balance delta: %+v", analysis.Accounts)
	}
	if !guardV3TestHasFinding(findings, "automatic_wallet_sol_delta") || !guardV3TestHasFinding(findings, "automatic_token_balance_changes") {
		t.Fatalf("automatic balance findings missing: %+v", findings)
	}
}

func TestEvaluateTransactionGuardV3AutomaticBalancesWithholdsTruncatedCoverage(t *testing.T) {
	wallet := guardV3Base58Encode(guardV3TestKey(23))
	decoded := transactionGuardDecodedTransaction{Available: true, Complete: true, StaticAccounts: []transactionGuardDecodedAccount{{Address: wallet, Writable: true}}}
	addresses := []string{wallet}
	accounts := []*services.SolanaAccountInfo{{Owner: guardV3SystemProgramID, Lamports: 10}}
	analysis, findings := evaluateTransactionGuardV3AutomaticBalances(decoded, wallet, addresses, 2, false, addresses, addresses, accounts, accounts)
	if analysis.Complete || analysis.Status != "evidence_incomplete" {
		t.Fatalf("truncated coverage was treated as complete: %+v", analysis)
	}
	if !guardV3TestHasFinding(findings, "automatic_balance_coverage_incomplete") {
		t.Fatalf("coverage finding missing: %+v", findings)
	}
}

func TestEvaluateTransactionGuardV3AutomaticBalancesDetectsClosedTokenAccount(t *testing.T) {
	wallet := guardV3Base58Encode(guardV3TestKey(24))
	tokenAccount := guardV3Base58Encode(guardV3TestKey(25))
	decoded := transactionGuardDecodedTransaction{Available: true, Complete: true, StaticAccounts: []transactionGuardDecodedAccount{{Address: tokenAccount, Writable: true}}}
	pre := []*services.SolanaAccountInfo{guardV3AutomaticTokenAccountInfo(guardV3TestKey(26), guardV3TestKey(24), 50, 2_039_280)}
	post := []*services.SolanaAccountInfo{nil}
	analysis, findings := evaluateTransactionGuardV3AutomaticBalances(decoded, wallet, []string{tokenAccount}, 1, true, []string{tokenAccount}, []string{tokenAccount}, pre, post)
	if !analysis.Complete || analysis.ClosedAccountCount != 1 || !analysis.Accounts[0].AccountClosed {
		t.Fatalf("closed token account was not captured: %+v", analysis)
	}
	if !guardV3TestHasFinding(findings, "automatic_token_account_closed") {
		t.Fatalf("closed-account finding missing: %+v", findings)
	}
}

func guardV3AutomaticTokenAccountInfo(mint, owner []byte, amount uint64, lamports int64) *services.SolanaAccountInfo {
	data := make([]byte, 165)
	copy(data[:32], mint)
	copy(data[32:64], owner)
	binary.LittleEndian.PutUint64(data[64:72], amount)
	return &services.SolanaAccountInfo{
		Owner: guardV3SPLTokenProgramID, Lamports: lamports,
		Data: []any{base64.StdEncoding.EncodeToString(data), "base64"},
	}
}
