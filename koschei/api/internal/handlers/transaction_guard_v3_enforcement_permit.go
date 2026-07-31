package handlers

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	transactionGuardEnforcementPermitVersion   = "koschei-enforcement-permit-v1"
	transactionGuardEnforcementPermitAlgorithm = "Ed25519"
	defaultTransactionGuardPermitTTLSeconds    = 45
	minimumTransactionGuardPermitTTLSeconds    = 5
	maximumTransactionGuardPermitTTLSeconds    = 120
)

type transactionGuardEnforcementPermitPayload struct {
	Version                string `json:"version"`
	PermitID               string `json:"permit_id"`
	Nonce                  string `json:"nonce"`
	KeyID                  string `json:"key_id"`
	Algorithm              string `json:"algorithm"`
	IssuedAt               string `json:"issued_at"`
	ExpiresAt              string `json:"expires_at"`
	Network                string `json:"network"`
	Wallet                 string `json:"wallet"`
	Origin                 string `json:"origin"`
	TransactionFingerprint string `json:"transaction_fingerprint"`
	Action                 string `json:"action"`
	RiskLevel              string `json:"risk_level"`
	RiskIndex              int    `json:"risk_index"`
	GuardComplete          bool   `json:"guard_complete"`
	WarnApprovalRequired   bool   `json:"warn_approval_required"`
	GuardVersion           string `json:"guard_version"`
	AnalysisVersion        string `json:"analysis_version"`
	RequestID              string `json:"request_id"`
	DecisionHash           string `json:"decision_hash"`
	SignedUIIntentID       string `json:"signed_ui_intent_id,omitempty"`
	UISummaryHash          string `json:"ui_summary_hash,omitempty"`
}

type transactionGuardEnforcementPermit struct {
	Requested        bool                                     `json:"requested"`
	Required         bool                                     `json:"required"`
	Available        bool                                     `json:"available"`
	Complete         bool                                     `json:"complete"`
	Status           string                                   `json:"status"`
	Algorithm        string                                   `json:"algorithm,omitempty"`
	KeyID            string                                   `json:"key_id,omitempty"`
	VerificationKey  string                                   `json:"verification_key,omitempty"`
	Payload          transactionGuardEnforcementPermitPayload `json:"payload"`
	CanonicalPayload string                                   `json:"canonical_payload,omitempty"`
	CanonicalSHA256  string                                   `json:"canonical_sha256,omitempty"`
	Signature        string                                   `json:"signature,omitempty"`
	Limitations      []string                                 `json:"limitations"`
}

type transactionGuardPermitDecisionCommitment struct {
	Action          string                           `json:"action"`
	RiskLevel       string                           `json:"risk_level"`
	RiskIndex       int                              `json:"risk_index"`
	Summary         string                           `json:"summary"`
	Findings        []transactionFirewallFinding     `json:"findings"`
	ProgramPolicy   transactionGuardProgramPolicy    `json:"program_policy"`
	IntentPolicy    transactionGuardIntentPolicy     `json:"intent_policy"`
	ThreatStatus    string                           `json:"threat_status"`
	ThreatRiskLevel string                           `json:"threat_risk_level,omitempty"`
	ThreatRiskIndex int                              `json:"threat_risk_index"`
	CPIStatus       string                           `json:"cpi_status"`
	AuthorityStatus string                           `json:"authority_status"`
}

func transactionGuardV3BaseEvidenceComplete(
	assessment transactionFirewallAssessment,
	program transactionGuardProgramPolicy,
	intent transactionGuardIntentPolicy,
	decoded transactionGuardDecodedTransaction,
	threat transactionGuardThreatHistoryAnalysis,
	cpi transactionGuardCPIFlowAnalysis,
	authority transactionGuardAuthoritySurfaceAnalysis,
) bool {
	threatComplete := !threat.Required || threat.Complete
	cpiComplete := !cpi.Required || cpi.Complete
	authorityComplete := !authority.Required || authority.Complete
	return assessment.SimulationOK && program.Complete && intent.Complete && decoded.Complete && threatComplete && cpiComplete && authorityComplete
}

func issueTransactionGuardV3EnforcementPermit(
	r *http.Request,
	input transactionGuardV2Request,
	requestID string,
	assessment transactionFirewallAssessment,
	program transactionGuardProgramPolicy,
	intent transactionGuardIntentPolicy,
	decoded transactionGuardDecodedTransaction,
	threat transactionGuardThreatHistoryAnalysis,
	cpi transactionGuardCPIFlowAnalysis,
	authority transactionGuardAuthoritySurfaceAnalysis,
	baseComplete bool,
	now time.Time,
) (transactionGuardEnforcementPermit, []transactionFirewallFinding) {
	required := envBool("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", false)
	permit := transactionGuardEnforcementPermit{
		Requested: true,
		Required:  required,
		Available: false,
		Complete:  false,
		Status:    "not_issued",
		Payload:   transactionGuardEnforcementPermitPayload{},
		Limitations: []string{
			"Wallets and extensions must pin a trusted Koschei enforcement verification key; a key returned in the same response is bootstrap metadata only.",
			"The permit authorizes only the exact transaction fingerprint, wallet, origin and decision until its short expiration time.",
		},
	}
	action := strings.ToLower(strings.TrimSpace(assessment.Action))
	if action != "allow" && action != "warn" {
		permit.Complete = true
		permit.Status = "not_issuable_for_decision"
		return permit, nil
	}
	if !baseComplete {
		permit.Status = "guard_incomplete"
		permit.Limitations = append(permit.Limitations, "A signing permit cannot be issued until every required Guard evidence check is complete.")
		return permit, transactionGuardEnforcementPermitUnavailableFinding(required, permit.Status)
	}

	wallet := strings.TrimSpace(input.Wallet)
	if wallet == "" {
		permit.Status = "wallet_unavailable"
		permit.Limitations = append(permit.Limitations, "The Guard request did not declare the wallet that would sign the transaction.")
		return permit, transactionGuardEnforcementPermitUnavailableFinding(required, permit.Status)
	}
	origin := transactionGuardV3PermitOrigin(r, decoded.SignedIntent)
	if origin == "" {
		permit.Status = "origin_unavailable"
		permit.Limitations = append(permit.Limitations, "No verified signed-intent origin or HTTP Origin was available for permit binding.")
		return permit, transactionGuardEnforcementPermitUnavailableFinding(required, permit.Status)
	}

	privateKey, publicKey, keyID, err := transactionGuardV3EnforcementSigningKey()
	if err != nil {
		permit.Status = "signing_key_unavailable"
		permit.Limitations = append(permit.Limitations, "Koschei enforcement signing is not configured or the configured key is invalid.")
		return permit, transactionGuardEnforcementPermitUnavailableFinding(required, permit.Status)
	}

	now = now.UTC().Truncate(time.Second)
	ttl := time.Duration(transactionGuardV3PermitTTLSeconds()) * time.Second
	decisionHash, err := transactionGuardV3PermitDecisionHash(assessment, program, intent, threat, cpi, authority)
	if err != nil {
		permit.Status = "decision_commitment_failed"
		permit.Limitations = append(permit.Limitations, "The Guard decision commitment could not be created.")
		return permit, transactionGuardEnforcementPermitUnavailableFinding(required, permit.Status)
	}
	permitID, err := transactionGuardV3RandomPermitValue("tgp")
	if err != nil {
		permit.Status = "secure_random_unavailable"
		return permit, transactionGuardEnforcementPermitUnavailableFinding(required, permit.Status)
	}
	nonce, err := transactionGuardV3RandomPermitValue("nonce")
	if err != nil {
		permit.Status = "secure_random_unavailable"
		return permit, transactionGuardEnforcementPermitUnavailableFinding(required, permit.Status)
	}

	payload := transactionGuardEnforcementPermitPayload{
		Version: transactionGuardEnforcementPermitVersion,
		PermitID: permitID,
		Nonce: nonce,
		KeyID: keyID,
		Algorithm: transactionGuardEnforcementPermitAlgorithm,
		IssuedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(ttl).Format(time.RFC3339),
		Network: strings.TrimSpace(input.Network),
		Wallet: wallet,
		Origin: origin,
		TransactionFingerprint: transactionFingerprint(input.Transaction),
		Action: action,
		RiskLevel: strings.ToLower(strings.TrimSpace(assessment.RiskLevel)),
		RiskIndex: assessment.RiskIndex,
		GuardComplete: true,
		WarnApprovalRequired: action == "warn",
		GuardVersion: transactionGuardVersion,
		AnalysisVersion: transactionGuardV3AnalysisVersion,
		RequestID: requestID,
		DecisionHash: decisionHash,
	}
	if decoded.SignedIntent.Complete {
		payload.SignedUIIntentID = strings.TrimSpace(decoded.SignedIntent.IntentID)
		payload.UISummaryHash = strings.TrimSpace(decoded.SignedIntent.UISummaryHash)
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		permit.Status = "canonical_payload_failed"
		return permit, transactionGuardEnforcementPermitUnavailableFinding(required, permit.Status)
	}
	signature := ed25519.Sign(privateKey, canonical)
	canonicalHash := sha256.Sum256(canonical)
	permit.Available = true
	permit.Complete = true
	permit.Status = "issued"
	permit.Algorithm = transactionGuardEnforcementPermitAlgorithm
	permit.KeyID = keyID
	permit.VerificationKey = base64.StdEncoding.EncodeToString(publicKey)
	permit.Payload = payload
	permit.CanonicalPayload = string(canonical)
	permit.CanonicalSHA256 = "sha256:" + hex.EncodeToString(canonicalHash[:])
	permit.Signature = base64.StdEncoding.EncodeToString(signature)
	return permit, nil
}

func transactionGuardV3PermitOrigin(r *http.Request, signed transactionGuardV3SignedIntentAssessment) string {
	if signed.Complete {
		if origin := normalizeTransactionGuardV3Origin(signed.UIOrigin); origin != "" {
			return origin
		}
	}
	if r == nil {
		return ""
	}
	return normalizeTransactionGuardV3Origin(r.Header.Get("Origin"))
}

func transactionGuardV3EnforcementSigningKey() (ed25519.PrivateKey, ed25519.PublicKey, string, error) {
	raw := strings.TrimSpace(os.Getenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY"))
	if raw == "" {
		return nil, nil, "", fmt.Errorf("enforcement signing key is empty")
	}
	decoded, err := transactionGuardV3DecodePrivateKey(raw)
	if err != nil {
		return nil, nil, "", err
	}
	var privateKey ed25519.PrivateKey
	switch len(decoded) {
	case ed25519.SeedSize:
		privateKey = ed25519.NewKeyFromSeed(decoded)
	case ed25519.PrivateKeySize:
		privateKey = ed25519.PrivateKey(append([]byte{}, decoded...))
	default:
		return nil, nil, "", fmt.Errorf("enforcement private key must contain a 32-byte seed or 64-byte private key")
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, "", fmt.Errorf("derive enforcement public key")
	}
	keyID := strings.TrimSpace(os.Getenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID"))
	if keyID == "" {
		hash := sha256.Sum256(publicKey)
		keyID = "tgk_" + hex.EncodeToString(hash[:8])
	}
	if len(keyID) > 80 {
		return nil, nil, "", fmt.Errorf("enforcement key id is too long")
	}
	return privateKey, publicKey, keyID, nil
}

func transactionGuardV3DecodePrivateKey(raw string) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(raw); err == nil {
		return decoded, nil
	}
	if decoded, err := hex.DecodeString(raw); err == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("enforcement private key is not valid base64 or hex")
}

func transactionGuardV3PermitTTLSeconds() int {
	value := defaultTransactionGuardPermitTTLSeconds
	if raw := strings.TrimSpace(os.Getenv("TRANSACTION_GUARD_ENFORCEMENT_PERMIT_TTL_SECONDS")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			value = parsed
		}
	}
	if value < minimumTransactionGuardPermitTTLSeconds {
		return minimumTransactionGuardPermitTTLSeconds
	}
	if value > maximumTransactionGuardPermitTTLSeconds {
		return maximumTransactionGuardPermitTTLSeconds
	}
	return value
}

func transactionGuardV3PermitDecisionHash(
	assessment transactionFirewallAssessment,
	program transactionGuardProgramPolicy,
	intent transactionGuardIntentPolicy,
	threat transactionGuardThreatHistoryAnalysis,
	cpi transactionGuardCPIFlowAnalysis,
	authority transactionGuardAuthoritySurfaceAnalysis,
) (string, error) {
	commitment := transactionGuardPermitDecisionCommitment{
		Action: assessment.Action,
		RiskLevel: assessment.RiskLevel,
		RiskIndex: assessment.RiskIndex,
		Summary: assessment.Summary,
		Findings: append([]transactionFirewallFinding{}, assessment.Findings...),
		ProgramPolicy: program,
		IntentPolicy: intent,
		ThreatStatus: threat.Status,
		ThreatRiskLevel: threat.HighestRiskLevel,
		ThreatRiskIndex: threat.HighestRiskIndex,
		CPIStatus: cpi.Status,
		AuthorityStatus: authority.Status,
	}
	encoded, err := json.Marshal(commitment)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

func transactionGuardV3RandomPermitValue(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(value), nil
}

func transactionGuardEnforcementPermitUnavailableFinding(required bool, status string) []transactionFirewallFinding {
	severity := "info"
	if required {
		severity = "high"
	}
	return []transactionFirewallFinding{{
		Code: "enforcement_permit_unavailable",
		Severity: severity,
		Title: "Cryptographic wallet enforcement permit is unavailable",
		Evidence: compactGuardV3Evidence("status=" + status),
		Score: 0,
	}}
}
