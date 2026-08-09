package handlers

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"koschei/api/internal/runtimecfg"
)

const transactionGuardEnforcementPermitVersion = "koschei-transaction-guard-permit-v1"
const transactionGuardStateBoundPermitVersion = "koschei-transaction-guard-permit-v2"

type transactionGuardEnforcementPermitClaims struct {
	Version                string `json:"version"`
	KeyID                  string `json:"key_id"`
	RequestID              string `json:"request_id"`
	TransactionFingerprint string `json:"transaction_fingerprint"`
	Network                string `json:"network"`
	Wallet                 string `json:"wallet,omitempty"`
	Action                 string `json:"action"`
	GuardVersion           string `json:"guard_version"`
	StateWitnessVersion    string `json:"state_witness_version,omitempty"`
	StateWitnessHash       string `json:"state_witness_hash,omitempty"`
	StateAccountRoot       string `json:"state_account_root_sha256,omitempty"`
	PreStateSlot           int64  `json:"pre_state_slot,omitempty"`
	SimulationSlot         int64  `json:"simulation_slot,omitempty"`
	IssuedAt               string `json:"issued_at"`
	ExpiresAt              string `json:"expires_at"`
}

type transactionGuardEnforcementPermit struct {
	Version   string                                  `json:"version"`
	Algorithm string                                  `json:"algorithm"`
	KeyID     string                                  `json:"key_id"`
	PublicKey string                                  `json:"public_key"`
	Claims    transactionGuardEnforcementPermitClaims `json:"claims"`
	Token     string                                  `json:"token"`
}

type transactionGuardEnforcementState struct {
	Required             bool
	StateWitnessRequired bool
	Configured           bool
	Issued               bool
	Status               string
	Permit               *transactionGuardEnforcementPermit
}

func buildTransactionGuardEnforcementState(input transactionGuardV2Request, requestID string, assessment transactionFirewallAssessment, guardComplete bool, now time.Time) transactionGuardEnforcementState {
	return buildTransactionGuardEnforcementStateWithWitness(input, requestID, assessment, guardComplete, now, nil)
}

func buildTransactionGuardEnforcementStateWithWitness(input transactionGuardV2Request, requestID string, assessment transactionFirewallAssessment, guardComplete bool, now time.Time, witness *transactionGuardStateWitness) transactionGuardEnforcementState {
	cfg := runtimecfg.Load().Guard
	state := transactionGuardEnforcementState{
		Required:             cfg.RequirePermit || cfg.RequireStateWitness,
		StateWitnessRequired: cfg.RequireStateWitness,
		Configured:           cfg.PrivateKeyConfigured && strings.TrimSpace(cfg.KeyID) != "",
		Status:               "not_required",
	}
	if !cfg.RequirePermit && !cfg.RequireStateWitness && !cfg.PrivateKeyConfigured {
		return state
	}
	if cfg.RequireStateWitness && !cfg.RequirePermit {
		state.Status = "state_witness_requires_permit"
		return state
	}
	if assessment.Action != "allow" || !guardComplete {
		state.Status = "not_eligible"
		return state
	}
	if cfg.RequireStateWitness && (witness == nil || !witness.Complete || strings.TrimSpace(witness.BindingHash) == "") {
		state.Status = "state_witness_unavailable"
		return state
	}
	if !state.Configured {
		state.Status = "signer_unconfigured"
		return state
	}
	privateKey, err := parseTransactionGuardPrivateKey(os.Getenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY"))
	if err != nil {
		state.Configured = false
		state.Status = "signer_invalid"
		return state
	}
	var permit transactionGuardEnforcementPermit
	if cfg.RequireStateWitness {
		permit, err = signTransactionGuardEnforcementPermitWithWitness(privateKey, cfg.KeyID, cfg.PermitTTL, input, requestID, assessment, now, witness)
	} else {
		permit, err = signTransactionGuardEnforcementPermit(privateKey, cfg.KeyID, cfg.PermitTTL, input, requestID, assessment, now)
	}
	if err != nil {
		state.Status = "signing_failed"
		return state
	}
	state.Issued = true
	state.Status = "issued"
	state.Permit = &permit
	return state
}

func signTransactionGuardEnforcementPermit(privateKey ed25519.PrivateKey, keyID string, ttl time.Duration, input transactionGuardV2Request, requestID string, assessment transactionFirewallAssessment, now time.Time) (transactionGuardEnforcementPermit, error) {
	return signTransactionGuardEnforcementPermitWithWitness(privateKey, keyID, ttl, input, requestID, assessment, now, nil)
}

func signTransactionGuardEnforcementPermitWithWitness(privateKey ed25519.PrivateKey, keyID string, ttl time.Duration, input transactionGuardV2Request, requestID string, assessment transactionFirewallAssessment, now time.Time, witness *transactionGuardStateWitness) (transactionGuardEnforcementPermit, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return transactionGuardEnforcementPermit{}, errors.New("invalid ed25519 private key size")
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return transactionGuardEnforcementPermit{}, errors.New("enforcement key id is required")
	}
	if assessment.Action != "allow" {
		return transactionGuardEnforcementPermit{}, errors.New("only allow decisions may receive enforcement permits")
	}
	if ttl < 10*time.Second || ttl > 10*time.Minute {
		return transactionGuardEnforcementPermit{}, errors.New("enforcement permit ttl is outside policy bounds")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	permitVersion := transactionGuardEnforcementPermitVersion
	claims := transactionGuardEnforcementPermitClaims{
		Version:                permitVersion,
		KeyID:                  keyID,
		RequestID:              strings.TrimSpace(requestID),
		TransactionFingerprint: transactionFingerprint(input.Transaction),
		Network:                strings.TrimSpace(input.Network),
		Wallet:                 strings.TrimSpace(input.Wallet),
		Action:                 "allow",
		GuardVersion:           transactionGuardVersion,
		IssuedAt:               now.Format(time.RFC3339Nano),
		ExpiresAt:              now.Add(ttl).Format(time.RFC3339Nano),
	}
	if witness != nil {
		if !witness.Complete || strings.TrimSpace(witness.BindingHash) == "" || strings.TrimSpace(witness.AccountRoot) == "" {
			return transactionGuardEnforcementPermit{}, errors.New("state witness is incomplete")
		}
		if strings.TrimSpace(witness.TransactionFingerprint) != claims.TransactionFingerprint {
			return transactionGuardEnforcementPermit{}, errors.New("state witness transaction fingerprint mismatch")
		}
		permitVersion = transactionGuardStateBoundPermitVersion
		claims.Version = permitVersion
		claims.StateWitnessVersion = witness.Version
		claims.StateWitnessHash = witness.BindingHash
		claims.StateAccountRoot = witness.AccountRoot
		claims.PreStateSlot = witness.PreStateSlot
		claims.SimulationSlot = witness.SimulationSlot
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return transactionGuardEnforcementPermit{}, err
	}
	signature := ed25519.Sign(privateKey, payload)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	payloadPart := base64.RawURLEncoding.EncodeToString(payload)
	signaturePart := base64.RawURLEncoding.EncodeToString(signature)
	return transactionGuardEnforcementPermit{
		Version:   permitVersion,
		Algorithm: "Ed25519",
		KeyID:     keyID,
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		Claims:    claims,
		Token:     payloadPart + "." + signaturePart,
	}, nil
}

func parseTransactionGuardPrivateKey(raw string) (ed25519.PrivateKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("enforcement private key is empty")
	}
	decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	}
	for _, decode := range decoders {
		decoded, err := decode(raw)
		if err != nil {
			continue
		}
		switch len(decoded) {
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(decoded), nil
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(append([]byte(nil), decoded...)), nil
		}
	}
	return nil, errors.New("enforcement private key must decode to a 32-byte Ed25519 seed or 64-byte private key")
}

func transactionGuardPermitPublicKeyFingerprint(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:8])
}

func applyTransactionGuardEnforcementRequirement(input transactionGuardV2Request, requestID string, assessment transactionFirewallAssessment, guardComplete bool, now time.Time) (transactionFirewallAssessment, transactionGuardEnforcementState) {
	return applyTransactionGuardEnforcementRequirementWithWitness(input, requestID, assessment, guardComplete, now, nil)
}

func applyTransactionGuardEnforcementRequirementWithWitness(input transactionGuardV2Request, requestID string, assessment transactionFirewallAssessment, guardComplete bool, now time.Time, witness *transactionGuardStateWitness) (transactionFirewallAssessment, transactionGuardEnforcementState) {
	state := buildTransactionGuardEnforcementStateWithWitness(input, requestID, assessment, guardComplete, now, witness)
	if state.Required && assessment.Action == "allow" && !state.Issued {
		assessment.Action = "withhold"
		assessment.RiskLevel = "unknown"
		if state.StateWitnessRequired && state.Status == "state_witness_unavailable" {
			assessment.Summary = "Transaction Guard withheld enforcement because the required state witness was unavailable."
		} else {
			assessment.Summary = "Transaction Guard withheld enforcement because the required signed permit was unavailable."
		}
	}
	return assessment, state
}

func attachTransactionGuardEnforcementResponse(response map[string]any, state transactionGuardEnforcementState) {
	response["enforcement_enabled"] = state.Configured
	response["enforcement_permit_required"] = state.Required
	response["state_witness_required"] = state.StateWitnessRequired
	response["enforcement_permit_issued"] = state.Issued
	response["enforcement_permit_status"] = state.Status
	if state.Permit != nil {
		response["enforcement_permit"] = state.Permit
	}
}

func transactionGuardHTTPStatusWithEnforcement(assessment transactionFirewallAssessment, state transactionGuardEnforcementState) int {
	if guardProviderUnavailable(assessment) {
		return 503
	}
	if state.Required && !state.Issued && assessment.Action == "withhold" {
		return 503
	}
	return 200
}

func validateRequiredTransactionGuardEnforcementConfig() error {
	cfg := runtimecfg.Load().Guard
	if cfg.RequireStateWitness && !cfg.RequirePermit {
		return errors.New("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT must be true when state witness enforcement is required")
	}
	if !cfg.RequirePermit {
		return nil
	}
	if strings.TrimSpace(cfg.KeyID) == "" {
		return errors.New("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID is required when enforcement permits are mandatory")
	}
	if !cfg.PrivateKeyConfigured {
		return errors.New("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY is required when enforcement permits are mandatory")
	}
	_, err := parseTransactionGuardPrivateKey(os.Getenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY"))
	return err
}
