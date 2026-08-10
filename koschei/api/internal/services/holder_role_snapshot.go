package services

import "strings"

// HolderRoleSnapshotInput is the provider-neutral on-chain snapshot consumed by
// holder-role analysis. Fetching and optional entity labeling deliberately live
// outside this contract so third-party enrichment can never block concentration
// evidence.
type HolderRoleSnapshotInput struct {
	TotalSupply           float64
	Largest               []SolanaLargestTokenAccount
	TokenAccounts         []*SolanaAccountInfo
	OwnerAccounts         map[string]*SolanaAccountInfo
	OwnerMetadataComplete bool
}

// SolanaHolderOwnerAddresses returns the unique controlling owner wallets from
// jsonParsed token-account snapshots while preserving first-seen order.
func SolanaHolderOwnerAddresses(tokenAccounts []*SolanaAccountInfo) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, info := range tokenAccounts {
		if info == nil {
			continue
		}
		owner := holderRoleParsedOwner(info.Data)
		if owner == "" || seen[owner] {
			continue
		}
		seen[owner] = true
		out = append(out, owner)
	}
	return out
}

// AnalyzeSolanaHolderRolesSnapshot is pure with respect to RPC/provider data:
// it performs no network calls and no third-party identity lookups. Unknown
// owners remain risk-bearing. This function is the canonical core used when
// Koschei already fetched a complete snapshot through its RPC transport layer.
func AnalyzeSolanaHolderRolesSnapshot(input HolderRoleSnapshotInput) HolderRoleAnalysis {
	totalSupply := input.TotalSupply
	largest := append([]SolanaLargestTokenAccount{}, input.Largest...)
	out := HolderRoleAnalysis{
		Status: "unavailable", ConcentrationBasis: "raw_supply", Supply: totalSupply,
		Accounts: []HolderRoleAccount{}, Limitations: []string{},
	}
	if totalSupply <= 0 || len(largest) == 0 {
		out.Limitations = append(out.Limitations, "Token supply and largest-account evidence are required for holder-role resolution.")
		return out
	}
	if len(largest) > 20 {
		largest = largest[:20]
	}
	if len(input.TokenAccounts) == 0 {
		out.Status = "token_account_owner_resolution_unavailable"
		out.Limitations = append(out.Limitations, "Top token accounts could not be resolved to controlling owner wallets.")
		return out
	}

	owners := make([]string, len(largest))
	for i := range largest {
		if i < len(input.TokenAccounts) && input.TokenAccounts[i] != nil {
			owners[i] = holderRoleParsedOwner(input.TokenAccounts[i].Data)
		}
	}
	ownerInfoByAddress := input.OwnerAccounts
	if ownerInfoByAddress == nil {
		ownerInfoByAddress = map[string]*SolanaAccountInfo{}
	}
	if !input.OwnerMetadataComplete {
		out.Limitations = append(out.Limitations, "Owner-wallet account metadata could not be fully fetched; unresolved wallets remain included in risk concentration.")
	}

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
			Rank: i + 1, TokenAccount: strings.TrimSpace(account.Address), OwnerWallet: owners[i], OwnerProgram: ownerProgram,
			Balance: holderRoleRound(balance, 8), RawPercentage: holderRoleRound(rawPct, 4),
			Role: role, Confidence: confidence, ExcludedFromHolderRisk: excluded, Evidence: append([]string{}, evidence...),
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
