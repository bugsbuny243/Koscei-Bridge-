package handlers

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	transactionGuardV3SignedIntentVersion = "koschei-ui-intent-v1"
	transactionGuardV3MaxIntentLifetime   = 30 * time.Minute
	transactionGuardV3IntentClockSkew     = 2 * time.Minute
)

type transactionGuardV3Request struct {
	Transaction      string                          `json:"transaction"`
	Encoding         string                          `json:"encoding"`
	Network          string                          `json:"network"`
	Wallet           string                          `json:"wallet"`
	ExpectedPrograms []string                        `json:"expected_programs"`
	RequiredPrograms []string                        `json:"required_programs"`
	BlockedPrograms  []string                        `json:"blocked_programs"`
	Accounts         []transactionGuardAccount       `json:"accounts"`
	SignedIntent     *transactionGuardV3SignedIntent `json:"signed_intent,omitempty"`
}

func (input transactionGuardV3Request) guardV2Request() transactionGuardV2Request {
	return transactionGuardV2Request{
		Transaction: input.Transaction, Encoding: input.Encoding, Network: input.Network, Wallet: input.Wallet,
		ExpectedPrograms: append([]string(nil), input.ExpectedPrograms...),
		RequiredPrograms: append([]string(nil), input.RequiredPrograms...),
		BlockedPrograms:  append([]string(nil), input.BlockedPrograms...),
		Accounts:         append([]transactionGuardAccount(nil), input.Accounts...),
	}
}

type transactionGuardV3SignedIntent struct {
	Version                string                    `json:"version"`
	IntentID               string                    `json:"intent_id"`
	Nonce                  string                    `json:"nonce"`
	IssuedAt               string                    `json:"issued_at"`
	ExpiresAt              string                    `json:"expires_at"`
	Network                string                    `json:"network"`
	Wallet                 string                    `json:"wallet"`
	TransactionFingerprint string                    `json:"transaction_fingerprint"`
	UIOrigin               string                    `json:"ui_origin"`
	UISummaryHash          string                    `json:"ui_summary_hash"`
	ExpectedPrograms       []string                  `json:"expected_programs"`
	RequiredPrograms       []string                  `json:"required_programs"`
	BlockedPrograms        []string                  `json:"blocked_programs"`
	Accounts               []transactionGuardAccount `json:"accounts"`
	Signer                 string                    `json:"signer"`
	Signature              string                    `json:"signature"`
}

type transactionGuardV3SignedIntentAssessment struct {
	Requested          bool     `json:"requested"`
	Required           bool     `json:"required"`
	Available          bool     `json:"available"`
	Complete           bool     `json:"complete"`
	Verified           bool     `json:"verified"`
	Status             string   `json:"status"`
	IntentID           string   `json:"intent_id,omitempty"`
	Signer             string   `json:"signer,omitempty"`
	UIOrigin           string   `json:"ui_origin,omitempty"`
	UISummaryHash      string   `json:"ui_summary_hash,omitempty"`
	IssuedAt           string   `json:"issued_at,omitempty"`
	ExpiresAt          string   `json:"expires_at,omitempty"`
	CanonicalHash      string   `json:"canonical_hash,omitempty"`
	SignatureVerified  bool     `json:"signature_verified"`
	FingerprintMatched bool     `json:"fingerprint_matched"`
	WalletMatched      bool     `json:"wallet_matched"`
	NetworkMatched     bool     `json:"network_matched"`
	PolicyMatched      bool     `json:"policy_matched"`
	OriginMatched      bool     `json:"origin_matched"`
	Mismatches         []string `json:"mismatches"`
	Limitations        []string `json:"limitations"`
}

type transactionGuardV3SignedIntentPayload struct {
	Version                string                    `json:"version"`
	IntentID               string                    `json:"intent_id"`
	Nonce                  string                    `json:"nonce"`
	IssuedAt               string                    `json:"issued_at"`
	ExpiresAt              string                    `json:"expires_at"`
	Network                string                    `json:"network"`
	Wallet                 string                    `json:"wallet"`
	TransactionFingerprint string                    `json:"transaction_fingerprint"`
	UIOrigin               string                    `json:"ui_origin"`
	UISummaryHash          string                    `json:"ui_summary_hash"`
	ExpectedPrograms       []string                  `json:"expected_programs"`
	RequiredPrograms       []string                  `json:"required_programs"`
	BlockedPrograms        []string                  `json:"blocked_programs"`
	Accounts               []transactionGuardAccount `json:"accounts"`
	Signer                 string                    `json:"signer"`
}

type transactionGuardV3SignedPolicyPayload struct {
	ExpectedPrograms []string                  `json:"expected_programs"`
	RequiredPrograms []string                  `json:"required_programs"`
	BlockedPrograms  []string                  `json:"blocked_programs"`
	Accounts         []transactionGuardAccount `json:"accounts"`
}

func evaluateTransactionGuardV3SignedIntent(input transactionGuardV2Request, signed *transactionGuardV3SignedIntent, actualFingerprint, requestOrigin string, now time.Time, required bool) (transactionGuardV3SignedIntentAssessment, []transactionFirewallFinding) {
	assessment := transactionGuardV3SignedIntentAssessment{
		Requested: signed != nil, Required: required, Complete: !required && signed == nil,
		Status: "not_requested", Mismatches: []string{}, Limitations: []string{},
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if signed == nil {
		if !required {
			return assessment, nil
		}
		assessment.Status = "required_intent_missing"
		return assessment, []transactionFirewallFinding{{
			Code: "signed_ui_intent_required", Severity: "high", Title: "Signed UI intent is required",
			Evidence: "TRANSACTION_GUARD_REQUIRE_SIGNED_INTENT is enabled but the request did not include signed_intent.", Score: 30,
		}}
	}
	assessment.Available = true
	assessment.IntentID = strings.TrimSpace(signed.IntentID)
	assessment.Signer = strings.TrimSpace(signed.Signer)
	assessment.UIOrigin = strings.TrimSpace(signed.UIOrigin)
	assessment.UISummaryHash = strings.ToLower(strings.TrimSpace(signed.UISummaryHash))

	payload, canonical, policyCanonical, issuedAt, expiresAt, err := canonicalTransactionGuardV3SignedIntent(*signed)
	if err != nil {
		assessment.Status = "malformed_signed_intent"
		assessment.Mismatches = append(assessment.Mismatches, err.Error())
		return assessment, []transactionFirewallFinding{{
			Code: "signed_ui_intent_malformed", Severity: "critical", Title: "Signed UI intent is malformed",
			Evidence: compactGuardV3Evidence(err.Error()), Score: 80,
		}}
	}
	assessment.IssuedAt = payload.IssuedAt
	assessment.ExpiresAt = payload.ExpiresAt
	hash := sha256.Sum256(canonical)
	assessment.CanonicalHash = hex.EncodeToString(hash[:])

	signerBytes, signerErr := decodeSolanaPublicKey(payload.Signer)
	signatureBytes, signatureErr := decodeTransactionGuardV3IntentSignature(signed.Signature)
	if signerErr != nil || len(signerBytes) != ed25519.PublicKeySize || signatureErr != nil || len(signatureBytes) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(signerBytes), canonical, signatureBytes) {
		assessment.Status = "signature_invalid"
		assessment.Mismatches = append(assessment.Mismatches, "The signed intent signature did not verify against the declared signer.")
		return assessment, []transactionFirewallFinding{{
			Code: "signed_ui_intent_signature_invalid", Severity: "critical", Title: "Signed UI intent signature is invalid",
			Evidence: "The canonical UI intent payload was not verified by the declared Ed25519 signer.", Score: 100,
		}}
	}
	assessment.SignatureVerified = true

	findings := []transactionFirewallFinding{}
	actualFingerprint = strings.TrimSpace(actualFingerprint)
	assessment.FingerprintMatched = payload.TransactionFingerprint == actualFingerprint
	if !assessment.FingerprintMatched {
		assessment.Mismatches = append(assessment.Mismatches, "Signed transaction fingerprint does not match the serialized transaction.")
		findings = append(findings, transactionFirewallFinding{
			Code: "signed_ui_intent_transaction_mismatch", Severity: "critical", Title: "UI intent is bound to a different transaction",
			Evidence: fmt.Sprintf("signed=%s actual=%s", payload.TransactionFingerprint, actualFingerprint), Score: 100,
		})
	}
	assessment.NetworkMatched = payload.Network == strings.TrimSpace(input.Network)
	if !assessment.NetworkMatched {
		assessment.Mismatches = append(assessment.Mismatches, "Signed network does not match the Guard request network.")
		findings = append(findings, transactionFirewallFinding{
			Code: "signed_ui_intent_network_mismatch", Severity: "critical", Title: "Signed UI intent network does not match",
			Evidence: fmt.Sprintf("signed_network=%s request_network=%s", payload.Network, strings.TrimSpace(input.Network)), Score: 100,
		})
	}
	requestWallet := strings.TrimSpace(input.Wallet)
	assessment.WalletMatched = payload.Wallet == requestWallet && payload.Signer == requestWallet
	if !assessment.WalletMatched {
		assessment.Mismatches = append(assessment.Mismatches, "Signed wallet or signer does not match the Guard request wallet.")
		findings = append(findings, transactionFirewallFinding{
			Code: "signed_ui_intent_wallet_mismatch", Severity: "critical", Title: "Signed UI intent wallet does not match",
			Evidence: fmt.Sprintf("signed_wallet=%s signer=%s request_wallet=%s", payload.Wallet, payload.Signer, requestWallet), Score: 100,
		})
	}
	requestPolicyCanonical, policyErr := canonicalTransactionGuardV3RequestPolicy(input)
	assessment.PolicyMatched = policyErr == nil && bytes.Equal(policyCanonical, requestPolicyCanonical)
	if !assessment.PolicyMatched {
		assessment.Mismatches = append(assessment.Mismatches, "Signed program or account policy differs from the Guard request policy.")
		findings = append(findings, transactionFirewallFinding{
			Code: "signed_ui_intent_policy_mismatch", Severity: "critical", Title: "Signed UI policy was changed",
			Evidence: "The signed expected/required/blocked program lists or account limits differ from the policy evaluated by Guard.", Score: 80,
		})
	}
	assessment.OriginMatched = true
	requestOrigin = normalizeTransactionGuardV3Origin(requestOrigin)
	if requestOrigin == "" {
		assessment.Limitations = append(assessment.Limitations, "The HTTP Origin header was unavailable; origin binding was preserved in the signature but not independently matched to the request transport.")
	} else if payload.UIOrigin != requestOrigin {
		assessment.OriginMatched = false
		assessment.Mismatches = append(assessment.Mismatches, "Signed UI origin differs from the HTTP Origin header.")
		findings = append(findings, transactionFirewallFinding{
			Code: "signed_ui_intent_origin_mismatch", Severity: "critical", Title: "Signed UI origin does not match the request origin",
			Evidence: fmt.Sprintf("signed_origin=%s request_origin=%s", payload.UIOrigin, requestOrigin), Score: 80,
		})
	}
	if now.Before(issuedAt.Add(-transactionGuardV3IntentClockSkew)) {
		assessment.Mismatches = append(assessment.Mismatches, "Signed UI intent was issued in the future.")
		findings = append(findings, transactionFirewallFinding{Code: "signed_ui_intent_not_yet_valid", Severity: "high", Title: "Signed UI intent is not yet valid", Evidence: payload.IssuedAt, Score: 50})
	}
	if now.After(expiresAt.Add(transactionGuardV3IntentClockSkew)) {
		assessment.Mismatches = append(assessment.Mismatches, "Signed UI intent has expired.")
		findings = append(findings, transactionFirewallFinding{Code: "signed_ui_intent_expired", Severity: "high", Title: "Signed UI intent has expired", Evidence: payload.ExpiresAt, Score: 50})
	}
	assessment.Complete = assessment.SignatureVerified && assessment.FingerprintMatched && assessment.NetworkMatched && assessment.WalletMatched && assessment.PolicyMatched && assessment.OriginMatched && len(assessment.Mismatches) == 0
	assessment.Verified = assessment.Complete
	if assessment.Complete {
		assessment.Status = "verified_signed_ui_intent"
		findings = append(findings, transactionFirewallFinding{
			Code: "signed_ui_intent_verified", Severity: "info", Title: "Signed UI intent verified",
			Evidence: fmt.Sprintf("intent_id=%s signer=%s canonical_hash=%s", payload.IntentID, payload.Signer, assessment.CanonicalHash), Score: 0,
		})
	} else {
		assessment.Status = "signed_ui_intent_mismatch"
	}
	assessment.Limitations = append(assessment.Limitations, "Nonce replay storage is not required for read-only analysis; transaction submission remains outside Koschei Guard.")
	return assessment, uniqueGuardV3Findings(findings)
}

func canonicalTransactionGuardV3SignedIntent(signed transactionGuardV3SignedIntent) (transactionGuardV3SignedIntentPayload, []byte, []byte, time.Time, time.Time, error) {
	issuedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(signed.IssuedAt))
	if err != nil {
		return transactionGuardV3SignedIntentPayload{}, nil, nil, time.Time{}, time.Time{}, fmt.Errorf("issued_at must be RFC3339")
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(signed.ExpiresAt))
	if err != nil {
		return transactionGuardV3SignedIntentPayload{}, nil, nil, time.Time{}, time.Time{}, fmt.Errorf("expires_at must be RFC3339")
	}
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > transactionGuardV3MaxIntentLifetime {
		return transactionGuardV3SignedIntentPayload{}, nil, nil, time.Time{}, time.Time{}, fmt.Errorf("signed intent lifetime must be greater than zero and no more than 30 minutes")
	}
	if strings.TrimSpace(signed.Version) != transactionGuardV3SignedIntentVersion {
		return transactionGuardV3SignedIntentPayload{}, nil, nil, time.Time{}, time.Time{}, fmt.Errorf("unsupported signed intent version")
	}
	if strings.TrimSpace(signed.IntentID) == "" || strings.TrimSpace(signed.Nonce) == "" {
		return transactionGuardV3SignedIntentPayload{}, nil, nil, time.Time{}, time.Time{}, fmt.Errorf("intent_id and nonce are required")
	}
	if strings.TrimSpace(signed.Wallet) == "" || strings.TrimSpace(signed.Signer) == "" || strings.TrimSpace(signed.TransactionFingerprint) == "" {
		return transactionGuardV3SignedIntentPayload{}, nil, nil, time.Time{}, time.Time{}, fmt.Errorf("wallet, signer and transaction_fingerprint are required")
	}
	if normalizeTransactionGuardV3Origin(signed.UIOrigin) == "" {
		return transactionGuardV3SignedIntentPayload{}, nil, nil, time.Time{}, time.Time{}, fmt.Errorf("ui_origin is required")
	}
	summaryHash := strings.ToLower(strings.TrimSpace(signed.UISummaryHash))
	if decoded, err := hex.DecodeString(summaryHash); err != nil || len(decoded) != sha256.Size {
		return transactionGuardV3SignedIntentPayload{}, nil, nil, time.Time{}, time.Time{}, fmt.Errorf("ui_summary_hash must be a 32-byte hexadecimal SHA-256 digest")
	}
	policyInput := transactionGuardV2Request{
		ExpectedPrograms: append([]string(nil), signed.ExpectedPrograms...), RequiredPrograms: append([]string(nil), signed.RequiredPrograms...),
		BlockedPrograms: append([]string(nil), signed.BlockedPrograms...), Accounts: append([]transactionGuardAccount(nil), signed.Accounts...),
	}
	if err := validateTransactionGuardInput(&policyInput); err != nil {
		return transactionGuardV3SignedIntentPayload{}, nil, nil, time.Time{}, time.Time{}, fmt.Errorf("signed intent policy is invalid: %w", err)
	}
	sortTransactionGuardV3Policy(&policyInput)
	payload := transactionGuardV3SignedIntentPayload{
		Version: transactionGuardV3SignedIntentVersion, IntentID: strings.TrimSpace(signed.IntentID), Nonce: strings.TrimSpace(signed.Nonce),
		IssuedAt: issuedAt.UTC().Format(time.RFC3339), ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
		Network: strings.TrimSpace(signed.Network), Wallet: strings.TrimSpace(signed.Wallet),
		TransactionFingerprint: strings.TrimSpace(signed.TransactionFingerprint), UIOrigin: normalizeTransactionGuardV3Origin(signed.UIOrigin),
		UISummaryHash: summaryHash, ExpectedPrograms: policyInput.ExpectedPrograms, RequiredPrograms: policyInput.RequiredPrograms,
		BlockedPrograms: policyInput.BlockedPrograms, Accounts: policyInput.Accounts, Signer: strings.TrimSpace(signed.Signer),
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return transactionGuardV3SignedIntentPayload{}, nil, nil, time.Time{}, time.Time{}, err
	}
	policyCanonical, err := json.Marshal(transactionGuardV3SignedPolicyPayload{
		ExpectedPrograms: payload.ExpectedPrograms, RequiredPrograms: payload.RequiredPrograms,
		BlockedPrograms: payload.BlockedPrograms, Accounts: payload.Accounts,
	})
	return payload, canonical, policyCanonical, issuedAt.UTC(), expiresAt.UTC(), err
}

func canonicalTransactionGuardV3RequestPolicy(input transactionGuardV2Request) ([]byte, error) {
	copyInput := transactionGuardV2Request{
		ExpectedPrograms: append([]string(nil), input.ExpectedPrograms...), RequiredPrograms: append([]string(nil), input.RequiredPrograms...),
		BlockedPrograms: append([]string(nil), input.BlockedPrograms...), Accounts: append([]transactionGuardAccount(nil), input.Accounts...),
	}
	if err := validateTransactionGuardInput(&copyInput); err != nil {
		return nil, err
	}
	sortTransactionGuardV3Policy(&copyInput)
	return json.Marshal(transactionGuardV3SignedPolicyPayload{
		ExpectedPrograms: copyInput.ExpectedPrograms, RequiredPrograms: copyInput.RequiredPrograms,
		BlockedPrograms: copyInput.BlockedPrograms, Accounts: copyInput.Accounts,
	})
}

func sortTransactionGuardV3Policy(input *transactionGuardV2Request) {
	if input == nil {
		return
	}
	if input.ExpectedPrograms == nil {
		input.ExpectedPrograms = []string{}
	}
	if input.RequiredPrograms == nil {
		input.RequiredPrograms = []string{}
	}
	if input.BlockedPrograms == nil {
		input.BlockedPrograms = []string{}
	}
	if input.Accounts == nil {
		input.Accounts = []transactionGuardAccount{}
	}
	sort.Strings(input.ExpectedPrograms)
	sort.Strings(input.RequiredPrograms)
	sort.Strings(input.BlockedPrograms)
	sort.SliceStable(input.Accounts, func(i, j int) bool {
		left := input.Accounts[i].Address + "|" + input.Accounts[i].Role + "|" + input.Accounts[i].Mint
		right := input.Accounts[j].Address + "|" + input.Accounts[j].Role + "|" + input.Accounts[j].Mint
		return left < right
	})
}

func decodeTransactionGuardV3IntentSignature(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
}

func normalizeTransactionGuardV3Origin(value string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(value), "/"))
}
