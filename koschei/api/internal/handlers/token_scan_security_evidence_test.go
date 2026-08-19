package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"koschei/api/internal/securityevidence"
)

func TestTokenScanResponseEmitsBackendSecurityEvidence(t *testing.T) {
	response := tokenScanResponse{
		Mint:                      "ExampleMint111",
		Network:                   "solana-mainnet",
		Score:                     61,
		RiskLevel:                 "medium",
		Supply:                    "1000000",
		Decimals:                  6,
		LargestHolderPercent:      24,
		TopTenPercent:             67,
		Findings:                  []string{"example"},
		TokenProgram:              "spl-token",
		Extensions:                []tokenExtensionAssessment{},
		ExtensionResolutionStatus: "not_applicable",
		ExtensionEvidenceComplete: true,
		TransferBehavior:          map[string]any{"standard_transfer": true},
		VisibilityLimitations:     []string{},
		CompatibilityWarnings:     []string{},
		FinalPolicy:               "review",
		VerifiedEvidence:          []string{},
		HolderAnalysisStatus:      "complete",
		AnalysisSummary:           map[string]any{},
		InvestigationReport:       map[string]any{},
	}

	source, err := marshalTokenScanResponseSource(response)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(source)
	expectedSourceDigest := hex.EncodeToString(sum[:])

	payload, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		ResponseSchemaVersion string                 `json:"response_schema_version"`
		SecurityEvidence      securityevidence.Event `json:"security_evidence"`
	}
	if err := json.Unmarshal(payload, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.ResponseSchemaVersion != customerInvestigationResponseSchemaVersion {
		t.Fatalf("unexpected response schema: %q", wire.ResponseSchemaVersion)
	}
	if err := wire.SecurityEvidence.Verify(); err != nil {
		t.Fatalf("emitted security evidence did not verify: %v", err)
	}
	if wire.SecurityEvidence.Subject.Chain != "solana" || wire.SecurityEvidence.Subject.Type != "token" || wire.SecurityEvidence.Subject.ID != response.Mint {
		t.Fatalf("unexpected evidence subject: %#v", wire.SecurityEvidence.Subject)
	}
	if len(wire.SecurityEvidence.SourceDigests) != 1 || wire.SecurityEvidence.SourceDigests[0] != expectedSourceDigest {
		t.Fatalf("event is not bound to exact trusted source bytes: %#v", wire.SecurityEvidence.SourceDigests)
	}
}

func TestTokenScanSecurityEvidenceChangesWhenTrustedResponseChanges(t *testing.T) {
	response := tokenScanResponse{
		Mint:                      "ExampleMint111",
		Network:                   "solana-mainnet",
		Score:                     80,
		RiskLevel:                 "low",
		TokenProgram:              "spl-token",
		Extensions:                []tokenExtensionAssessment{},
		ExtensionResolutionStatus: "not_applicable",
		ExtensionEvidenceComplete: true,
		TransferBehavior:          map[string]any{"standard_transfer": true},
		VisibilityLimitations:     []string{},
		CompatibilityWarnings:     []string{},
		FinalPolicy:               "allow",
		VerifiedEvidence:          []string{},
		AnalysisSummary:           map[string]any{},
		InvestigationReport:       map[string]any{},
	}

	firstPayload, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	response.Score = 20
	response.RiskLevel = "high"
	response.FinalPolicy = "block"
	secondPayload, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}

	var first, second struct {
		SecurityEvidence securityevidence.Event `json:"security_evidence"`
	}
	if err := json.Unmarshal(firstPayload, &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(secondPayload, &second); err != nil {
		t.Fatal(err)
	}
	if first.SecurityEvidence.EventSHA256 == second.SecurityEvidence.EventSHA256 {
		t.Fatal("security evidence identity did not change after trusted response mutation")
	}
}
