package handlers

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"
)

func (h *Handler) exposureToken2022Section(ctx context.Context, target, network string) map[string]any {
	ctx, cancel := context.WithTimeout(ctx, 6500*time.Millisecond)
	defer cancel()

	client := &http.Client{Timeout: 7 * time.Second}
	rpcURL := solanaRPCURL(network, os.Getenv("ALCHEMY_API_KEY"))
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

	if err := h.callSolanaRPC(ctx, client, rpcURL, network, "getAccountInfo", []interface{}{target, map[string]string{"encoding": "jsonParsed"}}, &account); err != nil {
		return map[string]any{"module_id": "token_2022_extensions", "module": "Token-2022 Extension Deep Scanner", "verified": false, "status": "rpc_unavailable", "is_token_2022": false, "evidence": []string{"Token-2022 extension evidence could not be collected from the RPC provider."}}
	}
	if account.Value == nil {
		return map[string]any{"module_id": "token_2022_extensions", "module": "Token-2022 Extension Deep Scanner", "verified": false, "status": "account_not_found", "is_token_2022": false, "evidence": []string{"Target account was not found; Token-2022 extension state is unavailable."}}
	}

	info := account.Value.Data.Parsed.Info
	isMint := strings.EqualFold(strings.TrimSpace(account.Value.Data.Parsed.Type), "mint")
	isToken2022 := account.Value.Owner == token2022ProgramID || strings.EqualFold(account.Value.Data.Program, "spl-token-2022")
	tokenProgram := "spl-token"
	if isToken2022 {
		tokenProgram = "token-2022"
	}
	if !isMint {
		return map[string]any{"module_id": "token_2022_extensions", "module": "Token-2022 Extension Deep Scanner", "verified": true, "status": "target_not_mint", "is_token_2022": isToken2022, "token_program": tokenProgram, "account_owner": account.Value.Owner, "evidence": []string{"Target exists, but it is not parsed as a token mint; Token-2022 mint extensions are not applicable."}}
	}

	extensions := []tokenExtensionAssessment{}
	penalty := 0
	behavior := map[string]any{"standard_transfer": true}
	visibility := []string{}
	compatibility := []string{}
	findings := []string{}
	if isToken2022 {
		extensions = parseToken2022Extensions(info)
		penalty, behavior, visibility, compatibility = summarizeToken2022Extensions(extensions)
		findings = token2022Findings(extensions)
		if len(extensions) == 0 {
			findings = append(findings, "Token is owned by the Token-2022 program and no active mint extensions were reported by the RPC parser.")
		}
	} else {
		findings = append(findings, "Token is owned by the classic SPL Token program; Token-2022 mint extensions are not active.")
	}

	riskIndex := exposureToken2022RiskIndex(isToken2022, penalty, extensions, visibility)
	return map[string]any{"module_id": "token_2022_extensions", "module": "Token-2022 Extension Deep Scanner", "verified": true, "status": exposureToken2022Status(isToken2022, extensions), "risk_index": riskIndex, "risk_level": exposureRiskLevelFromScore(riskIndex), "is_token_2022": isToken2022, "token_program": tokenProgram, "account_owner": account.Value.Owner, "extension_count": len(extensions), "extension_risk_penalty": penalty, "final_policy": tokenFinalPolicy(100-riskIndex, extensions, visibility), "extensions": extensions, "transfer_behavior": behavior, "visibility_limitations": visibility, "compatibility_warnings": compatibility, "evidence": findings}
}

func exposureToken2022Status(isToken2022 bool, extensions []tokenExtensionAssessment) string {
	if !isToken2022 {
		return "classic_spl_token"
	}
	if len(extensions) == 0 {
		return "token_2022_no_reported_extensions"
	}
	return "token_2022_extensions_present"
}

func exposureToken2022RiskIndex(isToken2022 bool, penalty int, extensions []tokenExtensionAssessment, visibility []string) int {
	if !isToken2022 {
		return 5
	}
	risk := 10 + penalty
	if len(visibility) > 0 && risk < 35 {
		risk = 35
	}
	for _, extension := range extensions {
		switch strings.ToLower(strings.TrimSpace(extension.Severity)) {
		case "critical":
			if risk < 85 {
				risk = 85
			}
		case "high":
			if risk < 65 {
				risk = 65
			}
		case "medium":
			if risk < 35 {
				risk = 35
			}
		}
	}
	if risk > 95 {
		return 95
	}
	if risk < 1 {
		return 1
	}
	return risk
}

func exposureRiskLevelFromScore(score int) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 65:
		return "high"
	case score >= 35:
		return "medium"
	default:
		return "low"
	}
}
