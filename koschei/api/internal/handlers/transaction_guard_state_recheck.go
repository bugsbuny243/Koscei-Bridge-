package handlers

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"koschei/api/internal/runtimecfg"
)

const transactionGuardStateRecheckVersion = "koschei-transaction-state-recheck-v1"
const transactionGuardStateRecheckMaxAccounts = 32

var (
	errTransactionGuardPermitExpired = errors.New("state-bound permit expired")
	errTransactionGuardPermitInvalid = errors.New("state-bound permit invalid")
)

type transactionGuardStateRecheckDecision struct {
	Version              string `json:"version"`
	Status               string `json:"status"`
	Action               string `json:"action"`
	StateUnchanged       bool   `json:"state_unchanged"`
	RequiresResimulation bool   `json:"requires_resimulation"`
	IssuedStateRoot      string `json:"issued_state_root_sha256,omitempty"`
	CurrentStateRoot     string `json:"current_state_root_sha256,omitempty"`
	SimulationSlot       int64  `json:"simulation_slot,omitempty"`
	CurrentStateSlot     int64  `json:"current_state_slot,omitempty"`
	SlotAdvance          uint64 `json:"slot_advance,omitempty"`
	Reason               string `json:"reason"`
}

func verifyTransactionGuardStateBoundPermitForRecheck(token, transaction, network string, witness transactionGuardStateWitness, now time.Time) (transactionGuardEnforcementPermitClaims, error) {
	cfg := runtimecfg.Load().Guard
	if strings.TrimSpace(cfg.KeyID) == "" || !cfg.PrivateKeyConfigured {
		return transactionGuardEnforcementPermitClaims{}, fmt.Errorf("%w: trusted enforcement signer is not configured", errTransactionGuardPermitInvalid)
	}
	privateKey, err := parseTransactionGuardPrivateKey(os.Getenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY"))
	if err != nil {
		return transactionGuardEnforcementPermitClaims{}, fmt.Errorf("%w: trusted enforcement signer is invalid", errTransactionGuardPermitInvalid)
	}
	claims, err := decodeAndVerifyTransactionGuardPermitToken(token, privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return transactionGuardEnforcementPermitClaims{}, err
	}
	if claims.Version != transactionGuardStateBoundPermitVersion || claims.KeyID != strings.TrimSpace(cfg.KeyID) {
		return transactionGuardEnforcementPermitClaims{}, fmt.Errorf("%w: unsupported permit version or key id", errTransactionGuardPermitInvalid)
	}
	if claims.Action != "allow" || claims.GuardVersion != transactionGuardVersion {
		return transactionGuardEnforcementPermitClaims{}, fmt.Errorf("%w: permit is not an allow decision for the current Guard version", errTransactionGuardPermitInvalid)
	}
	if strings.TrimSpace(network) == "" {
		network = "solana-mainnet"
	}
	if claims.Network != strings.TrimSpace(network) {
		return transactionGuardEnforcementPermitClaims{}, fmt.Errorf("%w: permit network mismatch", errTransactionGuardPermitInvalid)
	}
	fingerprint := transactionFingerprint(transaction)
	if fingerprint == "" || claims.TransactionFingerprint != fingerprint {
		return transactionGuardEnforcementPermitClaims{}, fmt.Errorf("%w: transaction fingerprint mismatch", errTransactionGuardPermitInvalid)
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, claims.IssuedAt)
	if err != nil {
		return transactionGuardEnforcementPermitClaims{}, fmt.Errorf("%w: malformed issued_at", errTransactionGuardPermitInvalid)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, claims.ExpiresAt)
	if err != nil || !expiresAt.After(issuedAt) {
		return transactionGuardEnforcementPermitClaims{}, fmt.Errorf("%w: malformed expiry", errTransactionGuardPermitInvalid)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if now.Before(issuedAt) {
		return transactionGuardEnforcementPermitClaims{}, fmt.Errorf("%w: permit is not active yet", errTransactionGuardPermitInvalid)
	}
	if !now.Before(expiresAt) {
		return transactionGuardEnforcementPermitClaims{}, errTransactionGuardPermitExpired
	}
	if err := validateTransactionGuardIssuedStateWitness(witness, claims); err != nil {
		return transactionGuardEnforcementPermitClaims{}, err
	}
	return claims, nil
}

func decodeAndVerifyTransactionGuardPermitToken(token string, publicKey ed25519.PublicKey) (transactionGuardEnforcementPermitClaims, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 2 || len(publicKey) != ed25519.PublicKeySize {
		return transactionGuardEnforcementPermitClaims{}, fmt.Errorf("%w: malformed token", errTransactionGuardPermitInvalid)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) == 0 {
		return transactionGuardEnforcementPermitClaims{}, fmt.Errorf("%w: malformed payload", errTransactionGuardPermitInvalid)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return transactionGuardEnforcementPermitClaims{}, fmt.Errorf("%w: malformed signature", errTransactionGuardPermitInvalid)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return transactionGuardEnforcementPermitClaims{}, fmt.Errorf("%w: signature verification failed", errTransactionGuardPermitInvalid)
	}
	var claims transactionGuardEnforcementPermitClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return transactionGuardEnforcementPermitClaims{}, fmt.Errorf("%w: malformed claims", errTransactionGuardPermitInvalid)
	}
	return claims, nil
}

func validateTransactionGuardIssuedStateWitness(witness transactionGuardStateWitness, claims transactionGuardEnforcementPermitClaims) error {
	if !witness.Complete || witness.Version != transactionGuardStateWitnessVersion || witness.Status != "complete" {
		return fmt.Errorf("%w: witness is incomplete", errTransactionGuardPermitInvalid)
	}
	if witness.TransactionFingerprint != claims.TransactionFingerprint || witness.Version != claims.StateWitnessVersion {
		return fmt.Errorf("%w: witness identity mismatch", errTransactionGuardPermitInvalid)
	}
	if witness.PreStateSlot != claims.PreStateSlot || witness.SimulationSlot != claims.SimulationSlot {
		return fmt.Errorf("%w: witness slot mismatch", errTransactionGuardPermitInvalid)
	}
	if witness.AccountCount != len(witness.Accounts) || witness.AccountCount < 1 || witness.AccountCount > transactionGuardStateRecheckMaxAccounts {
		return fmt.Errorf("%w: witness account set is invalid", errTransactionGuardPermitInvalid)
	}
	root, err := transactionGuardStateRootFromWitnessAccounts(witness.Accounts)
	if err != nil || root != witness.AccountRoot || root != claims.StateAccountRoot {
		return fmt.Errorf("%w: witness account root mismatch", errTransactionGuardPermitInvalid)
	}
	bindingHash, err := transactionGuardIssuedStateWitnessBindingHash(witness)
	if err != nil || bindingHash != witness.BindingHash || bindingHash != claims.StateWitnessHash {
		return fmt.Errorf("%w: witness binding mismatch", errTransactionGuardPermitInvalid)
	}
	return nil
}

func transactionGuardStateRootFromWitnessAccounts(accounts []transactionGuardStateWitnessAccount) (string, error) {
	if len(accounts) < 1 || len(accounts) > transactionGuardStateRecheckMaxAccounts {
		return "", fmt.Errorf("invalid state witness account count")
	}
	leaves := make([]transactionGuardStateRootLeaf, 0, len(accounts))
	seen := map[string]struct{}{}
	for _, account := range accounts {
		address := strings.TrimSpace(account.Address)
		stateHash := strings.ToLower(strings.TrimSpace(account.StateHash))
		if address == "" {
			return "", fmt.Errorf("empty state witness account address")
		}
		if _, exists := seen[address]; exists {
			return "", fmt.Errorf("duplicate state witness account address")
		}
		seen[address] = struct{}{}
		decodedHash, err := hex.DecodeString(stateHash)
		if err != nil || len(decodedHash) != sha256.Size {
			return "", fmt.Errorf("invalid state witness account hash")
		}
		leaves = append(leaves, transactionGuardStateRootLeaf{Address: address, StateHash: stateHash})
	}
	sort.Slice(leaves, func(i, j int) bool { return leaves[i].Address < leaves[j].Address })
	payload, err := json.Marshal(leaves)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func transactionGuardIssuedStateWitnessBindingHash(witness transactionGuardStateWitness) (string, error) {
	binding := transactionGuardStateBinding{
		Version:                witness.Version,
		TransactionFingerprint: strings.TrimSpace(witness.TransactionFingerprint),
		PreStateSlot:           witness.PreStateSlot,
		SimulationSlot:         witness.SimulationSlot,
		AccountRoot:            strings.ToLower(strings.TrimSpace(witness.AccountRoot)),
	}
	payload, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func evaluateTransactionGuardStateRecheck(claims transactionGuardEnforcementPermitClaims, currentRoot string, currentSlot int64) transactionGuardStateRecheckDecision {
	decision := transactionGuardStateRecheckDecision{
		Version:              transactionGuardStateRecheckVersion,
		Status:               "withhold",
		Action:               "recheck_required",
		StateUnchanged:       false,
		RequiresResimulation: true,
		IssuedStateRoot:      strings.ToLower(strings.TrimSpace(claims.StateAccountRoot)),
		CurrentStateRoot:     strings.ToLower(strings.TrimSpace(currentRoot)),
		SimulationSlot:       claims.SimulationSlot,
		CurrentStateSlot:     currentSlot,
		Reason:               "Current account-state evidence is incomplete.",
	}
	if currentSlot <= 0 || decision.CurrentStateRoot == "" {
		return decision
	}
	if claims.SimulationSlot <= 0 || currentSlot < claims.SimulationSlot {
		decision.Status = "withhold"
		decision.Reason = "The recheck provider returned state older than the signed simulation slot."
		return decision
	}
	decision.SlotAdvance = uint64(currentSlot - claims.SimulationSlot)
	if decision.CurrentStateRoot != decision.IssuedStateRoot {
		decision.Status = "state_changed"
		decision.Reason = "At least one witnessed account state changed after the signed Guard decision; run a fresh simulation."
		return decision
	}
	decision.Status = "state_unchanged"
	decision.Action = "permit_state_consistent"
	decision.StateUnchanged = true
	decision.RequiresResimulation = false
	decision.Reason = "The bounded witnessed account-state root still matches the signed Guard decision."
	return decision
}
