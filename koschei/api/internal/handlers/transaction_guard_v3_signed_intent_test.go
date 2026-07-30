package handlers

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"
)

func TestEvaluateTransactionGuardV3SignedIntentVerifiesWalletBinding(t *testing.T) {
	now := time.Date(2026, 7, 30, 4, 0, 0, 0, time.UTC)
	input, signed := guardV3TestSignedIntent(t, now)
	assessment, findings := evaluateTransactionGuardV3SignedIntent(input, &signed, "tx-fingerprint", "https://app.koschei.example", now.Add(time.Minute), true)
	if !assessment.Complete || !assessment.Verified || !assessment.SignatureVerified || !assessment.FingerprintMatched || !assessment.WalletMatched || !assessment.PolicyMatched || !assessment.OriginMatched {
		t.Fatalf("signed intent was not verified: %+v findings=%+v", assessment, findings)
	}
	if !guardV3TestHasFinding(findings, "signed_ui_intent_verified") {
		t.Fatalf("verified finding missing: %+v", findings)
	}
}

func TestEvaluateTransactionGuardV3SignedIntentBlocksTransactionSwap(t *testing.T) {
	now := time.Date(2026, 7, 30, 4, 0, 0, 0, time.UTC)
	input, signed := guardV3TestSignedIntent(t, now)
	assessment, findings := evaluateTransactionGuardV3SignedIntent(input, &signed, "different-fingerprint", "https://app.koschei.example", now.Add(time.Minute), false)
	if assessment.Complete || assessment.FingerprintMatched {
		t.Fatalf("transaction substitution was accepted: %+v", assessment)
	}
	if !guardV3TestHasFinding(findings, "signed_ui_intent_transaction_mismatch") {
		t.Fatalf("transaction mismatch finding missing: %+v", findings)
	}
}

func TestEvaluateTransactionGuardV3SignedIntentDetectsPolicyMutation(t *testing.T) {
	now := time.Date(2026, 7, 30, 4, 0, 0, 0, time.UTC)
	input, signed := guardV3TestSignedIntent(t, now)
	input.ExpectedPrograms = []string{guardV3Token2022ProgramID}
	assessment, findings := evaluateTransactionGuardV3SignedIntent(input, &signed, "tx-fingerprint", "https://app.koschei.example", now.Add(time.Minute), false)
	if assessment.Complete || assessment.PolicyMatched {
		t.Fatalf("policy mutation was accepted: %+v", assessment)
	}
	if !guardV3TestHasFinding(findings, "signed_ui_intent_policy_mismatch") {
		t.Fatalf("policy mismatch finding missing: %+v", findings)
	}
}

func TestEvaluateTransactionGuardV3SignedIntentRequiresEnvelopeWhenEnabled(t *testing.T) {
	assessment, findings := evaluateTransactionGuardV3SignedIntent(transactionGuardV2Request{}, nil, "fingerprint", "", time.Now().UTC(), true)
	if assessment.Complete || assessment.Status != "required_intent_missing" {
		t.Fatalf("required signed intent was not withheld: %+v", assessment)
	}
	if !guardV3TestHasFinding(findings, "signed_ui_intent_required") {
		t.Fatalf("required finding missing: %+v", findings)
	}
}

func guardV3TestSignedIntent(t *testing.T, issuedAt time.Time) (transactionGuardV2Request, transactionGuardV3SignedIntent) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	wallet := guardV3Base58Encode(publicKey)
	summary := sha256.Sum256([]byte("Send 1 token to the expected recipient"))
	input := transactionGuardV2Request{
		Network: "solana-mainnet", Wallet: wallet,
		ExpectedPrograms: []string{guardV3SPLTokenProgramID},
	}
	signed := transactionGuardV3SignedIntent{
		Version: transactionGuardV3SignedIntentVersion, IntentID: "intent-123", Nonce: "nonce-456",
		IssuedAt: issuedAt.Format(time.RFC3339), ExpiresAt: issuedAt.Add(10 * time.Minute).Format(time.RFC3339),
		Network: "solana-mainnet", Wallet: wallet, TransactionFingerprint: "tx-fingerprint",
		UIOrigin: "https://app.koschei.example", UISummaryHash: hex.EncodeToString(summary[:]),
		ExpectedPrograms: []string{guardV3SPLTokenProgramID}, Signer: wallet,
	}
	_, canonical, _, _, _, err := canonicalTransactionGuardV3SignedIntent(signed)
	if err != nil {
		t.Fatalf("canonical intent: %v", err)
	}
	signed.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return input, signed
}
