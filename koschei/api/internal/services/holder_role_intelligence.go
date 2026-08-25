package services

import (
	"context"
	"math"
	"sort"
	"strings"
)

const (
	solanaSystemProgramID     = "11111111111111111111111111111111"
	solanaIncineratorAddress  = "1nc1nerator11111111111111111111111111111111"
	pumpBondingCurveProgramID = "6EF8rrecthR5DkzZEXAPch3d4H6Wu1R5uWsTFTTF1F6P"
	pumpLiquidityProgramID    = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"
)

// HolderRoleAccount separates a token account from the wallet or PDA that
// controls it. Role labels are evidence-scoped and never claim real-world
// identity or malicious intent.
type HolderRoleAccount struct {
	Rank                   int      `json:"rank"`
	TokenAccount           string   `json:"token_account"`
	OwnerWallet            string   `json:"owner_wallet,omitempty"`
	OwnerProgram           string   `json:"owner_program,omitempty"`
	Balance                float64  `json:"balance"`
	RawPercentage          float64  `json:"raw_percentage"`
	CirculatingPercentage  float64  `json:"circulating_percentage,omitempty"`
	Role                   string   `json:"role"`
	Confidence             string   `json:"confidence"`
	ExcludedFromHolderRisk bool     `json:"excluded_from_holder_risk"`
	Evidence               []string `json:"evidence"`
	Label                  string   `json:"label,omitempty"`        // resolved entity label, e.g. "Binance · CEX"
	LabelEntity            string   `json:"label_entity,omitempty"` // raw entity, e.g. "Binance"
	LabelSource            string   `json:"label_source,omitempty"` // provenance, e.g. "helius_identity"
}

// HolderRoleAnalysis preserves raw supply concentration while also producing
// a role-aware concentration view that excludes only positively identified
// burn sinks and Pump protocol inventory. Unknown PDAs are never silently
// excluded.
type HolderRoleAnalysis struct {
	Available                    bool                `json:"available"`
	Status                       string              `json:"status"`
	RoleAdjusted                 bool                `json:"role_adjusted"`
	BlockingEvidenceGap          bool                `json:"blocking_evidence_gap"`
	ConcentrationBasis           string              `json:"concentration_basis"`
	Supply                       float64             `json:"supply"`
	CirculatingSupply            float64             `json:"circulating_supply"`
	RawTop1Percentage            float64             `json:"raw_top_1_percentage"`
	RawTop3Percentage            float64             `json:"raw_top_3_percentage"`
	RawTop10Percentage           float64             `json:"raw_top_10_percentage"`
	RawTop20Percentage           float64             `json:"raw_top_20_percentage"`
	EffectiveTop1Percentage      float64             `json:"top_1_percentage"`
	EffectiveTop3Percentage      float64             `json:"top_3_percentage"`
	EffectiveTop10Percentage     float64             `json:"top_10_percentage"`
	EffectiveTop20Percentage     float64             `json:"top_20_percentage"`
	ProtocolControlledPercentage float64             `json:"protocol_controlled_percentage"`
	BurnPercentage               float64             `json:"burn_percentage"`
	UnresolvedPercentage         float64             `json:"unresolved_percentage"`
	DominantRole                 string              `json:"dominant_role"`
	DominantOwnerWallet          string              `json:"dominant_owner_wallet,omitempty"`
	DominantOwnerProgram         string              `json:"dominant_owner_program,omitempty"`
	Accounts                     []HolderRoleAccount `json:"top_accounts"`
	Limitations                  []string            `json:"limitations"`
}

func AnalyzeSolanaHolderRoles(ctx context.Context, rpcURL string, totalSupply float64, largest []SolanaLargestTokenAccount) HolderRoleAnalysis {
	out := HolderRoleAnalysis{
		Status: "unavailable", ConcentrationBasis: "raw_supply", Supply: totalSupply,
		Accounts: []HolderRoleAccount{}, Limitations: []string{},
	}
	if totalSupply <= 0 || len(largest) == 0 || strings.TrimSpace(rpcURL) == "" {
		out.Limitations = append(out.Limitations, "Token supply, largest-account evidence and Solana RPC are required for holder-role resolution.")
		return out
	}
	if len(largest) > 20 {
		largest = largest[:20]
	}
	tokenAddresses := make([]string, 0, len(largest))
	for _, account := range largest {
		tokenAddresses = append(tokenAddresses, account.Address)
	}
	tokenInfos, err := SolanaGetMultipleAccountsJSONParsed(ctx, rpcURL, tokenAddresses)
	if err != nil {
		out.Status = "token_account_owner_resolution_unavailable"
		out.Limitations = append(out.Limitations, "Top token accounts could not be resolved to controlling owner wallets.")
		return out
	}

	owners := make([]string, len(largest))
	ownerList := []string{}
	ownerSeen := map[string]bool{}
	for i := range largest {
		if i < len(tokenInfos.Value) && tokenInfos.Value[i] != nil {
			owners[i] = holderRoleParsedOwner(tokenInfos.Value[i].Data)
		}
		if owners[i] != "" && !ownerSeen[owners[i]] {
			ownerSeen[owners[i]] = true
			ownerList = append(ownerList, owners[i])
		}
	}
	ownerInfoByAddress := map[string]*SolanaAccountInfo{}
	if len(ownerList) > 0 {
		if ownerInfos, ownerErr := SolanaGetMultipleAccountsJSONParsed(ctx, rpcURL, ownerList); ownerErr == nil {
			for i, address := range ownerList {
				if i < len(ownerInfos.Value) {
					ownerInfoByAddress[address] = ownerInfos.Value[i]
				}
			}
		} else {
			out.Limitations = append(out.Limitations, "Owner-wallet account metadata could not be fetched; unresolved wallets remain included in risk concentration.")
		}
	}

	// Helius Wallet API charges per request rather than per address. Resolve the
	// bounded Top-N owner set in one batch request instead of paying the same
	// 100-credit cost repeatedly for individual holders.
	ownerLabels := ResolveWalletLabels(ctx, rpcURL, ownerList)

	rawBalances := make([]float64, 0, len(largest))
	excludedBalance := 0.0
	protocolBalance := 0.0
	burnBalance := 0.0
	unresolvedBalance := 0.0
	for i, account := range largest {
		balance := solanaTokenFloat(account.SolanaTokenAmount)
		if balance < 0 {
			balance = 0
		}
		rawBalances = append(rawBalances, balance)
		rawPct := holderRolePercent(balance, totalSupply)
		role, confidence, excluded, ownerProgram, evidence := classifySolanaHolderOwner(owners[i], ownerInfoByAddress[owners[i]])
		row := HolderRoleAccount{
			Rank: i + 1, TokenAccount: account.Address, OwnerWallet: owners[i], OwnerProgram: ownerProgram,
			Balance: holderRoleRound(balance, 8), RawPercentage: holderRoleRound(rawPct, 4),
			Role: role, Confidence: confidence, ExcludedFromHolderRisk: excluded, Evidence: evidence,
		}
		if label := ownerLabels[owners[i]]; label != nil {
			if display := walletLabelDisplay(label); display != "" {
				row.Label = display
				row.LabelEntity = label.Entity
				row.LabelSource = label.Source
				row.Evidence = append(row.Evidence, "Wallet resolves to a known entity in the Helius identity database: "+display+". Label is sourced from a third-party dataset, not a Koschei claim.")
			}
		}
		if excluded {
			excludedBalance += balance
			if role == "burn_sink" {
				burnBalance += balance
			} else {
				protocolBalance += balance
			}
		}
		if role == "owner_unresolved" || role == "wallet_account_unavailable" || role == "program_controlled_unresolved" {
			unresolvedBalance += balance
			if i == 0 && rawPct >= 20 {
				out.BlockingEvidenceGap = true
			}
		}
		out.Accounts = append(out.Accounts, row)
	}

	out.RawTop1Percentage, out.RawTop3Percentage, out.RawTop10Percentage, out.RawTop20Percentage = holderRoleConcentration(rawBalances, totalSupply)
	out.CirculatingSupply = totalSupply - excludedBalance
	if out.CirculatingSupply <= 0 {
		out.BlockingEvidenceGap = true
		out.CirculatingSupply = 0
	}
	riskBalances := holderRoleRiskBalancesByOwner(out.Accounts)
	out.EffectiveTop1Percentage, out.EffectiveTop3Percentage, out.EffectiveTop10Percentage, out.EffectiveTop20Percentage = holderRoleConcentration(riskBalances, out.CirculatingSupply)
	for i := range out.Accounts {
		if !out.Accounts[i].ExcludedFromHolderRisk && out.CirculatingSupply > 0 {
			out.Accounts[i].CirculatingPercentage = holderRoleRound(holderRolePercent(out.Accounts[i].Balance, out.CirculatingSupply), 4)
		}
	}
	out.ProtocolControlledPercentage = holderRoleRound(holderRolePercent(protocolBalance, totalSupply), 4)
	out.BurnPercentage = holderRoleRound(holderRolePercent(burnBalance, totalSupply), 4)
	out.UnresolvedPercentage = holderRoleRound(holderRolePercent(unresolvedBalance, totalSupply), 4)
	if len(out.Accounts) > 0 {
		out.DominantRole = out.Accounts[0].Role
		out.DominantOwnerWallet = out.Accounts[0].OwnerWallet
		out.DominantOwnerProgram = out.Accounts[0].OwnerProgram
	}
	out.Available = true
	out.Status = "verified_role_resolution"
	out.RoleAdjusted = excludedBalance > 0 && !out.BlockingEvidenceGap && out.CirculatingSupply > 0
	if out.RoleAdjusted {
		out.ConcentrationBasis = "circulating_holder_distribution"
	}
	if out.BlockingEvidenceGap {
		out.Status = "dominant_holder_role_unresolved"
		out.Limitations = append(out.Limitations, "A dominant holder role remains unresolved; Koschei must not downgrade concentration risk until that account is classified.")
	}
	return out
}

func classifySolanaHolderOwner(ownerWallet string, info *SolanaAccountInfo) (string, string, bool, string, []string) {
	ownerWallet = strings.TrimSpace(ownerWallet)
	if strings.EqualFold(ownerWallet, solanaIncineratorAddress) {
		return "burn_sink", "high", true, "", []string{"Owner wallet matches the Solana incinerator address."}
	}
	if ownerWallet == "" {
		return "owner_unresolved", "low", false, "", []string{"Token-account owner wallet was not present in parsed RPC data."}
	}
	if info == nil {
		return "wallet_account_unavailable", "low", false, "", []string{"Owner wallet was resolved, but its account metadata was unavailable; it remains included in concentration risk."}
	}
	ownerProgram := strings.TrimSpace(info.Owner)
	switch {
	case strings.EqualFold(ownerProgram, pumpBondingCurveProgramID):
		return "pump_bonding_curve_or_protocol_vault", "high", true, ownerProgram, []string{"Owner account is controlled by the Pump bonding-curve program; this balance is protocol inventory, not a normal whale wallet."}
	case strings.EqualFold(ownerProgram, pumpLiquidityProgramID):
		return "pump_liquidity_vault", "high", true, ownerProgram, []string{"Owner account is controlled by the Pump AMM program; this balance is classified as protocol liquidity inventory."}
	case info.Executable:
		return "executable_program_controlled", "high", true, ownerProgram, []string{"The controlling owner account is executable program state rather than a normal user wallet."}
	case strings.EqualFold(ownerProgram, solanaSystemProgramID):
		return "externally_owned_wallet", "high", false, ownerProgram, []string{"Owner account is controlled by the Solana System Program and is treated as a normal wallet for concentration risk."}
	case ownerProgram == "":
		return "owner_unresolved", "low", false, ownerProgram, []string{"Owner program was not available; balance remains included in concentration risk."}
	default:
		return "program_controlled_unresolved", "medium", false, ownerProgram, []string{"Owner account is controlled by a non-System program, but its economic role is not positively identified; balance remains included until classified."}
	}
}

func holderRoleParsedOwner(raw any) string {
	data, _ := raw.(map[string]any)
	parsed, _ := data["parsed"].(map[string]any)
	info, _ := parsed["info"].(map[string]any)
	return strings.TrimSpace(anyString(info["owner"]))
}

func holderRoleRiskBalancesByOwner(accounts []HolderRoleAccount) []float64 {
	byOwner := map[string]float64{}
	for _, account := range accounts {
		if account.ExcludedFromHolderRisk || account.Balance <= 0 {
			continue
		}
		key := strings.TrimSpace(account.OwnerWallet)
		if key == "" {
			key = "token-account:" + strings.TrimSpace(account.TokenAccount)
		}
		byOwner[key] += account.Balance
	}
	values := make([]float64, 0, len(byOwner))
	for _, balance := range byOwner {
		values = append(values, balance)
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(values)))
	return values
}

func holderRoleConcentration(values []float64, denominator float64) (float64, float64, float64, float64) {
	if denominator <= 0 || len(values) == 0 {
		return 0, 0, 0, 0
	}
	var top1, top3, top10, top20 float64
	for i, value := range values {
		pct := holderRolePercent(value, denominator)
		if i == 0 {
			top1 = pct
		}
		if i < 3 {
			top3 += pct
		}
		if i < 10 {
			top10 += pct
		}
		if i < 20 {
			top20 += pct
		}
	}
	return holderRoleRound(top1, 4), holderRoleRound(top3, 4), holderRoleRound(top10, 4), holderRoleRound(top20, 4)
}

func holderRolePercent(value, denominator float64) float64 {
	if value <= 0 || denominator <= 0 {
		return 0
	}
	return value / denominator * 100
}

func holderRoleRound(value float64, digits int) float64 {
	factor := math.Pow10(digits)
	return math.Round(value*factor) / factor
}

func HolderRoleAnalysisMap(value HolderRoleAnalysis) map[string]any {
	return map[string]any{
		"available": value.Available, "status": value.Status, "role_adjusted": value.RoleAdjusted,
		"blocking_evidence_gap": value.BlockingEvidenceGap, "concentration_basis": value.ConcentrationBasis,
		"supply": value.Supply, "circulating_supply": value.CirculatingSupply,
		"raw_top_1_percentage": value.RawTop1Percentage, "raw_top_3_percentage": value.RawTop3Percentage,
		"raw_top_10_percentage": value.RawTop10Percentage, "raw_top_20_percentage": value.RawTop20Percentage,
		"top_1_percentage": value.EffectiveTop1Percentage, "top_3_percentage": value.EffectiveTop3Percentage,
		"top_10_percentage": value.EffectiveTop10Percentage, "top_20_percentage": value.EffectiveTop20Percentage,
		"protocol_controlled_percentage": value.ProtocolControlledPercentage, "burn_percentage": value.BurnPercentage,
		"unresolved_percentage": value.UnresolvedPercentage, "dominant_role": value.DominantRole,
		"dominant_owner_wallet": value.DominantOwnerWallet, "dominant_owner_program": value.DominantOwnerProgram,
		"top_accounts": value.Accounts, "observed_account_count": len(value.Accounts), "limitations": value.Limitations,
	}
}
