package handlers

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"koschei/api/internal/services"
)

// radarDetailHolderDistributionTransport collects the holder proof through
// Handler.callSolanaRPC, which means the same provider-independent RPC manager,
// failover and future Koschei-owned SOLANA_RPC_URL are used as the rest of the
// customer scan. Third-party wallet identity labels are deliberately excluded
// from this critical path.
func (h *Handler) radarDetailHolderDistributionTransport(parent context.Context, target, network string) (map[string]any, services.HolderRoleAnalysis) {
	if parent == nil {
		parent = context.Background()
	}
	target = strings.TrimSpace(target)
	network = strings.TrimSpace(network)
	if network == "" {
		network = "solana-mainnet"
	}
	if target == "" {
		return map[string]any{"available": false, "status": "target_missing", "top_accounts": []any{}}, services.HolderRoleAnalysis{}
	}

	ctx, cancel := context.WithTimeout(parent, 24*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 10 * time.Second}
	rpcURL := solanaRPCURL(network, os.Getenv("ALCHEMY_API_KEY"))

	var supply services.SolanaTokenSupplyResult
	if err := h.callSolanaRPC(ctx, client, rpcURL, network, "getTokenSupply", []any{target, map[string]any{"commitment": "confirmed"}}, &supply); err != nil {
		return map[string]any{"available": false, "status": "supply_unavailable", "error": compactRadarDetailError(err), "top_accounts": []any{}, "transport": "koschei_rpc_manager"}, services.HolderRoleAnalysis{}
	}

	var largest services.SolanaLargestAccountsResult
	if err := h.callSolanaRPC(ctx, client, rpcURL, network, "getTokenLargestAccounts", []any{target, map[string]any{"commitment": "confirmed"}}, &largest); err != nil {
		return map[string]any{"available": false, "status": "largest_accounts_unavailable", "error": compactRadarDetailError(err), "top_accounts": []any{}, "transport": "koschei_rpc_manager"}, services.HolderRoleAnalysis{}
	}
	if len(largest.Value) > 20 {
		largest.Value = largest.Value[:20]
	}

	tokenAddresses := make([]string, 0, len(largest.Value))
	for _, item := range largest.Value {
		if address := strings.TrimSpace(item.Address); address != "" {
			tokenAddresses = append(tokenAddresses, address)
		}
	}
	if len(tokenAddresses) == 0 {
		return map[string]any{"available": false, "status": "largest_accounts_empty", "top_accounts": []any{}, "transport": "koschei_rpc_manager"}, services.HolderRoleAnalysis{}
	}

	var tokenInfos services.SolanaMultipleAccountInfoResult
	if err := h.callSolanaRPC(ctx, client, rpcURL, network, "getMultipleAccounts", []any{tokenAddresses, map[string]any{"encoding": "jsonParsed", "commitment": "confirmed"}}, &tokenInfos); err != nil {
		return map[string]any{"available": false, "status": "token_account_owner_resolution_unavailable", "error": compactRadarDetailError(err), "top_accounts": []any{}, "transport": "koschei_rpc_manager"}, services.HolderRoleAnalysis{}
	}

	owners := services.SolanaHolderOwnerAddresses(tokenInfos.Value)
	ownerInfoByAddress := map[string]*services.SolanaAccountInfo{}
	ownerMetadataComplete := true
	if len(owners) > 0 {
		var ownerInfos services.SolanaMultipleAccountInfoResult
		if err := h.callSolanaRPC(ctx, client, rpcURL, network, "getMultipleAccounts", []any{owners, map[string]any{"encoding": "jsonParsed", "commitment": "confirmed"}}, &ownerInfos); err != nil {
			ownerMetadataComplete = false
		} else {
			for i, address := range owners {
				if i < len(ownerInfos.Value) {
					ownerInfoByAddress[address] = ownerInfos.Value[i]
				}
			}
		}
	}

	totalSupply := radarDetailTokenAmount(supply.Value)
	roles := services.AnalyzeSolanaHolderRolesSnapshot(services.HolderRoleSnapshotInput{
		TotalSupply: totalSupply, Largest: largest.Value, TokenAccounts: tokenInfos.Value,
		OwnerAccounts: ownerInfoByAddress, OwnerMetadataComplete: ownerMetadataComplete,
	})
	out := services.HolderRoleAnalysisMap(roles)
	out["decimals"] = supply.Value.Decimals
	out["largest_account_balance"] = 0.0
	if len(largest.Value) > 0 {
		out["largest_account_balance"] = radarDetailRound(radarDetailTokenAmount(largest.Value[0].SolanaTokenAmount), 6)
	}
	out["account_scope"] = "Token accounts resolved to owner wallets and owner programs through Koschei's Solana RPC transport; only positively identified protocol inventory or burn sinks are excluded from holder-risk concentration."
	out["transport"] = "koschei_rpc_manager"
	out["identity_enrichment_applied"] = false
	out["identity_enrichment_required_for_holder_verdict"] = false
	return out, roles
}
