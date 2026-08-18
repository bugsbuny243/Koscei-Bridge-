package handlers

import (
	"encoding/json"
	"strings"

	"koschei/api/internal/securityevidence"
)

type tokenScanResponseAlias tokenScanResponse

type tokenScanResponseWire struct {
	ResponseSchemaVersion string                  `json:"response_schema_version"`
	tokenScanResponseAlias
	SecurityEvidence      *securityevidence.Event `json:"security_evidence,omitempty"`
}

func tokenScanResponseBase(response tokenScanResponse) tokenScanResponseWire {
	return tokenScanResponseWire{
		ResponseSchemaVersion:  customerInvestigationResponseSchemaVersion,
		tokenScanResponseAlias: tokenScanResponseAlias(response),
	}
}

func marshalTokenScanResponseSource(response tokenScanResponse) ([]byte, error) {
	return json.Marshal(tokenScanResponseBase(response))
}

// MarshalJSON keeps the established token-scan response contract while adding
// a backend-generated Security Evidence Bus event. The event hashes the exact
// canonical response bytes before security_evidence is attached, avoiding a
// self-referential digest while preventing frontend/browser state from becoming
// trusted evidence authority.
func (response tokenScanResponse) MarshalJSON() ([]byte, error) {
	sourceBytes, err := marshalTokenScanResponseSource(response)
	if err != nil {
		return nil, err
	}

	score := response.Score
	event, err := securityevidence.BuildRadarEventV1(securityevidence.RadarReportInput{
		ReportJSON: sourceBytes,
		Subject: securityevidence.Subject{
			Chain: "solana",
			Type:  "token",
			ID:    response.Mint,
		},
		Window:   securityevidence.ObservationWindow{},
		Findings: tokenScanSecurityEvidenceFindings(response),
		Legacy:   &securityevidence.LegacyObservation{Score: &score},
	})
	if err != nil {
		return nil, err
	}
	if err := event.Verify(); err != nil {
		return nil, err
	}

	wire := tokenScanResponseBase(response)
	wire.SecurityEvidence = &event
	return json.Marshal(wire)
}

func tokenScanSecurityEvidenceFindings(response tokenScanResponse) []securityevidence.Finding {
	findings := []securityevidence.Finding{
		{
			ID:       "radar-policy",
			Kind:     "risk_policy",
			State:    securityevidence.StateObserved,
			Severity: strings.ToUpper(strings.TrimSpace(response.RiskLevel)),
			Summary:  strings.TrimSpace(response.FinalPolicy),
		},
		{
			ID:       "mint-authority",
			Kind:     "authority_state",
			State:    securityevidence.StateObserved,
			Severity: authorityEvidenceSeverity(response.MintAuthority),
			Summary:  authorityEvidenceSummary("mint", response.MintAuthority),
		},
		{
			ID:       "freeze-authority",
			Kind:     "authority_state",
			State:    securityevidence.StateObserved,
			Severity: authorityEvidenceSeverity(response.FreezeAuthority),
			Summary:  authorityEvidenceSummary("freeze", response.FreezeAuthority),
		},
	}

	holderState := securityevidence.StateObserved
	holderSeverity := holderConcentrationEvidenceSeverity(response.LargestHolderPercent, response.TopTenPercent)
	if strings.EqualFold(strings.TrimSpace(response.HolderAnalysisStatus), "unavailable") {
		holderState = securityevidence.StateUnavailable
		holderSeverity = "UNKNOWN"
	}
	findings = append(findings, securityevidence.Finding{
		ID:       "holder-concentration",
		Kind:     "holder_concentration",
		State:    holderState,
		Severity: holderSeverity,
		Summary:  "largest-holder and top-ten concentration from the trusted token scan response",
	})

	extensionState := securityevidence.StateNotApplicable
	extensionSeverity := "INFO"
	extensionSummary := "token is not owned by Token-2022"
	if response.Token2022 {
		extensionState = securityevidence.StateObserved
		extensionSummary = strings.TrimSpace(response.ExtensionResolutionStatus)
		if !response.ExtensionEvidenceComplete {
			extensionState = securityevidence.StateUnavailable
			extensionSeverity = "UNKNOWN"
		} else if response.ExtensionRiskPenalty > 0 {
			extensionSeverity = "MEDIUM"
		}
	}
	findings = append(findings, securityevidence.Finding{
		ID:       "token-2022-extension-resolution",
		Kind:     "token_extension_state",
		State:    extensionState,
		Severity: extensionSeverity,
		Summary:  extensionSummary,
	})

	return findings
}

func authorityEvidenceSeverity(authority string) string {
	if strings.TrimSpace(authority) == "" {
		return "INFO"
	}
	return "HIGH"
}

func authorityEvidenceSummary(kind, authority string) string {
	if strings.TrimSpace(authority) == "" {
		return kind + " authority disabled"
	}
	return kind + " authority active"
}

func holderConcentrationEvidenceSeverity(topOne, topTen float64) string {
	switch {
	case topOne >= 50 || topTen >= 80:
		return "HIGH"
	case topOne >= 20 || topTen >= 60:
		return "MEDIUM"
	default:
		return "INFO"
	}
}
