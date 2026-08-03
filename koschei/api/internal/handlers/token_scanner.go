package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"koschei/api/internal/services"
	"koschei/api/internal/web3"
)

const token2022ProgramID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"

type tokenScanRequest struct {
	Mint    string `json:"mint"`
	Address string `json:"address"`
	Network string `json:"network"`
}

type tokenScanResponse struct {
	Mint                      string                           `json:"mint"`
	Network                   string                           `json:"network"`
	Score                     int                              `json:"score"`
	RiskLevel                 string                           `json:"risk_level"`
	Supply                    string                           `json:"supply"`
	Decimals                  int                              `json:"decimals"`
	MintAuthority             string                           `json:"mint_authority,omitempty"`
	FreezeAuthority           string                           `json:"freeze_authority,omitempty"`
	LargestHolderPercent      float64                          `json:"largest_holder_percent"`
	TopTenPercent             float64                          `json:"top_ten_percent"`
	Findings                  []string                         `json:"findings"`
	TokenProgram              string                           `json:"token_program"`
	Token2022                 bool                             `json:"token_2022"`
	Extensions                []tokenExtensionAssessment       `json:"extensions"`
	ExtensionRiskPenalty      int                              `json:"extension_risk_penalty"`
	ExtensionResolutionStatus string                           `json:"extension_resolution_status"`
	ExtensionEvidenceComplete bool                             `json:"extension_evidence_complete"`
	TransferBehavior          map[string]any                   `json:"transfer_behavior"`
	VisibilityLimitations     []string                         `json:"visibility_limitations"`
	CompatibilityWarnings     []string                         `json:"compatibility_warnings"`
	FinalPolicy               string                           `json:"final_policy"`
	HolderDistribution        map[string]any                   `json:"holder_distribution"`
	HolderIntelligence        services.HolderIntelligence      `json:"holder_intelligence"`
	HolderCluster             services.HolderClusterAnalysis   `json:"holder_cluster"`
	LaunchForensics           services.LaunchForensicsAnalysis `json:"launch_forensics"`
	VerifiedEvidence          []string                         `json:"verified_evidence"`
	Explanation               string                           `json:"explanation"`
	ExplanationV2             scanExplanationV2                `json:"explanation_v2"`
	HolderAnalysisStatus      string                           `json:"holder_analysis_status"`
	VerdictWithheld           bool                             `json:"verdict_withheld"`
	Disclaimer                string                           `json:"disclaimer"`
	AnalysisSummary           map[string]any                   `json:"analysis_summary"`
	InvestigationReport       map[string]any                   `json:"investigation_report"`
}

type rpcEnvelope struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (h *Handler) TokenScan(w http.ResponseWriter, r *http.Request) {
	var req tokenScanRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	mint := strings.TrimSpace(req.Mint)
	if mint == "" {
		mint = strings.TrimSpace(req.Address)
	}
	if mint == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mint required"})
		return
	}
	if req.Network == "" {
		req.Network = "solana-mainnet"
	}

	client := &http.Client{Timeout: 12 * time.Second}
	rpcURL := solanaRPCURL(req.Network, os.Getenv("ALCHEMY_API_KEY"))
	var supply struct {
		Value struct {
			Amount   string `json:"amount"`
			Decimals int    `json:"decimals"`
		} `json:"value"`
	}
	if err := h.callSolanaRPC(r.Context(), client, rpcURL, req.Network, "getTokenSupply", []interface{}{mint}, &supply); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "token mint not found or RPC request failed"})
		return
	}

	var account struct {
		Value *struct {
			Owner string `json:"owner"`
			Data  struct {
				Program string `json:"program"`
				Parsed  struct {
					Type string         `json:"type"`
					Info map[string]any `json:"info"`
				} `json:"parsed"`
				Space int `json:"space"`
			} `json:"data"`
		} `json:"value"`
	}
	_ = h.callSolanaRPC(r.Context(), client, rpcURL, req.Network, "getAccountInfo", []interface{}{mint, map[string]string{"encoding": "jsonParsed"}}, &account)

	holderCore := h.runHolderIntelligenceCore(r.Context(), mint, req.Network, "customer_token_scan")
	assembly := h.assembleUnifiedInvestigationReport(r.Context(), holderCore)
	analysisSummary := attachCustomerAnalysisSummary(&assembly)
	topOne, topTen, holderConcentrationAvailable := holderIntelligenceCoreConcentration(holderCore)

	score := 100
	findings := []string{}
	mintAuthority, freezeAuthority := "", ""
	tokenProgram := "spl-token"
	isToken2022 := false
	extensions := []tokenExtensionAssessment{}
	transferBehavior := map[string]any{"standard_transfer": true}
	visibilityLimitations := []string{}
	compatibilityWarnings := []string{}
	extensionPenalty := 0
	extensionResolutionStatus := "not_applicable"
	extensionEvidenceComplete := true

	if account.Value != nil {
		info := account.Value.Data.Parsed.Info
		mintAuthority = tokenInfoString(info, "mintAuthority")
		freezeAuthority = tokenInfoString(info, "freezeAuthority")
		if mintAuthority != "" {
			score -= 25
			findings = append(findings, "Mint authority is active and can create additional supply.")
		} else {
			findings = append(findings, "Mint authority is disabled.")
		}
		if freezeAuthority != "" {
			score -= 20
			findings = append(findings, "Freeze authority is active and can freeze token accounts.")
		} else {
			findings = append(findings, "Freeze authority is disabled.")
		}

		isToken2022 = account.Value.Owner == token2022ProgramID || strings.EqualFold(account.Value.Data.Program, "spl-token-2022")
		if isToken2022 {
			tokenProgram = "token-2022"
			extensions = parseToken2022Extensions(info)
			extensionResolutionStatus, extensionEvidenceComplete = token2022ExtensionResolution(true, account.Value.Data.Space, extensions)
			extensionPenalty, transferBehavior, visibilityLimitations, compatibilityWarnings = summarizeToken2022Extensions(extensions)
			score -= extensionPenalty
			findings = append(findings, token2022Findings(extensions)...)
			if !extensionEvidenceComplete {
				visibilityLimitations = append(visibilityLimitations, "Token-2022 account space indicates extension state, but the RPC parser did not expose the extension list.")
				compatibilityWarnings = append(compatibilityWarnings, "Transfer hook, permanent delegate, default frozen state, transfer fees, or pause controls cannot be ruled out until raw TLV extension state is decoded.")
				findings = append(findings, "Token-2022 extensions are unresolved; a safe verdict is withheld because transfer-control capabilities cannot be ruled out.")
			} else if len(extensions) == 0 {
				findings = append(findings, "Token is owned by the Token-2022 program and the resolved mint state reported no active extensions.")
			}
		}
	}

	findings = appendUniqueHolderCoreEvidence(findings, holderIntelligenceCoreEvidence(holderCore)...)
	if !holderConcentrationAvailable {
		findings = appendUniqueHolderCoreEvidence(findings, "Holder concentration was unavailable; missing evidence is not treated as a safety signal.")
	}

	if topOne >= 50 {
		score -= 35
		findings = append(findings, "The largest token account controls at least half of the supply.")
	} else if topOne >= 20 {
		score -= 20
		findings = append(findings, "The largest token account has a significant concentration.")
	}
	if topTen >= 80 {
		score -= 20
		findings = append(findings, "The ten largest token accounts control most of the supply.")
	}
	if score < 0 {
		score = 0
	}
	score = applyRepeatDominantRiskToLegacyScore(score, holderCore)
	if repeatRisk := holderIntelligenceCoreRepeatRisk(holderCore); repeatRisk > 0 {
		findings = appendUniqueHolderCoreEvidence(findings,
			fmt.Sprintf("Repeat-dominant holder evidence applies a %d/100 cross-token actor risk weight from the stored Koschei observation window.", repeatRisk),
		)
	}

	risk := tokenRiskLevel(score)
	policy := token2022FinalPolicy(score, extensions, visibilityLimitations, extensionEvidenceComplete)
	holderPolicy := holderIntelligenceCorePolicy(holderCore)
	if holderPolicy == "withhold" {
		policy = "withhold"
	}
	disclaimer := "Koschei provides read-only risk signals based on public on-chain data. Token extensions can be legitimate but may materially change transfer, authority, fee, privacy, or compatibility behavior. This is not financial advice."

	writeJSON(w, http.StatusOK, tokenScanResponse{
		Mint:                      mint,
		Network:                   req.Network,
		Score:                     score,
		RiskLevel:                 risk,
		Supply:                    supply.Value.Amount,
		Decimals:                  supply.Value.Decimals,
		MintAuthority:             mintAuthority,
		FreezeAuthority:           freezeAuthority,
		LargestHolderPercent:      roundPercent(topOne),
		TopTenPercent:             roundPercent(topTen),
		Findings:                  findings,
		TokenProgram:              tokenProgram,
		Token2022:                 isToken2022,
		Extensions:                extensions,
		ExtensionRiskPenalty:      extensionPenalty,
		ExtensionResolutionStatus: extensionResolutionStatus,
		ExtensionEvidenceComplete: extensionEvidenceComplete,
		TransferBehavior:          transferBehavior,
		VisibilityLimitations:     visibilityLimitations,
		CompatibilityWarnings:     compatibilityWarnings,
		FinalPolicy:               policy,
		HolderDistribution:        holderCore.Distribution,
		HolderIntelligence:        holderCore.Intelligence,
		HolderCluster:             holderCore.Cluster,
		LaunchForensics:           holderCore.LaunchForensics,
		VerifiedEvidence:          holderIntelligenceCoreEvidence(holderCore),
		Explanation:               holderIntelligenceCoreExplanation(holderCore),
		ExplanationV2:             holderIntelligenceCoreExplanationV2(holderCore),
		HolderAnalysisStatus:      holderIntelligenceCoreStatus(holderCore),
		VerdictWithheld:           holderPolicy == "withhold" || !extensionEvidenceComplete,
		Disclaimer:                disclaimer,
		AnalysisSummary:           analysisSummary,
		InvestigationReport:       assembly.Report,
	})
}

func tokenInfoString(info map[string]any, key string) string {
	value, exists := info[key]
	if !exists || value == nil {
		return ""
	}
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func (h *Handler) callSolanaRPC(ctx context.Context, client *http.Client, rpcURL, network, method string, params interface{}, target interface{}) error {
	if h != nil && h.SolanaRPC != nil {
		return h.SolanaRPC.Call(ctx, network, method, params, target, 0)
	}
	return callSolanaRPC(client, rpcURL, method, params, target)
}

func callSolanaRPC(client *http.Client, rpcURL, method string, params interface{}, target interface{}) error {
	body, err := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return err
	}
	resp, err := client.Post(rpcURL, "application/json", bytes.NewReader(body))
	if err != nil {
		web3.LogRPCFailure(method, rpcURL, 0, err)
		return err
	}
	defer resp.Body.Close()
	actualEndpoint := rpcURL
	if resp.Request != nil && resp.Request.URL != nil {
		actualEndpoint = resp.Request.URL.String()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("rpc status %d", resp.StatusCode)
		web3.LogRPCFailure(method, actualEndpoint, resp.StatusCode, err)
		return err
	}
	var envelope rpcEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		web3.LogRPCFailure(method, actualEndpoint, resp.StatusCode, err)
		return err
	}
	if envelope.Error != nil {
		err := fmt.Errorf("rpc error: %s", envelope.Error.Message)
		web3.LogRPCFailure(method, actualEndpoint, resp.StatusCode, err)
		return err
	}
	if err := json.Unmarshal(envelope.Result, target); err != nil {
		web3.LogRPCFailure(method, actualEndpoint, resp.StatusCode, err)
		return err
	}
	return nil
}

func roundPercent(value float64) float64 {
	return float64(int(value*100+0.5)) / 100
}
