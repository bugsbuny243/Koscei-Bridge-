package handlers

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"koschei/api/internal/services"
)

func (h *Handler) collectCompleteLPControlEvidence(ctx context.Context, network, mint, creator string, market services.TokenMarketSnapshot, source map[string]any) services.LPControlEvidence {
	rpc := h.lpRPC()
	lp := collectLPControlEvidence(ctx, rpc, network, mint, creator, market, source)
	switch lp.ReasonCode {
	case "amm_v4_layout_not_resolved":
		lp = collectRaydiumAMMV4Evidence(ctx, rpc, network, mint, creator, strings.TrimSpace(market.BestPairAddress))
	case "primary_pool_not_raydium", "unrecognized_raydium_pool_program":
		lp = collectProtocolLPControlEvidence(ctx, rpc, network, mint, creator, strings.TrimSpace(market.BestPairAddress))
	}
	lp.TokenMint = strings.TrimSpace(mint)
	if lp.PoolProgram == raydiumCPMMProgram || lp.PoolProgram == raydiumAMMV4Program {
		lp.ControlModel = "lp_token"
		lp.PositionModel = "fungible_lp_token"
		lp.LPSupplySource = "mint_supply"
	}
	if lp.EffectiveQuoteReserve == 0 {
		lp.EffectiveQuoteReserve = lp.QuoteReserve
	}
	if lp.Available && lp.TokenReserve > 0 && market.PriceUSD > 0 {
		// The token-vault reserve and timestamped reference price are primary.
		// The x2 value is an explicitly labelled balanced-pool estimate.
		lp.ReserveLiquidityUSD = math.Round(lp.TokenReserve*market.PriceUSD*2*100) / 100
		lp.ReserveValueSource = "direct_token_vault_reserve_x_market_price_x2"
		lp.EvidenceKeys = append(lp.EvidenceKeys, fmt.Sprintf("reserve_value:%s@%d", lp.TokenVault, lp.ReadSlot))
	}
	lp = resolveStreamflowLPTimeLock(ctx, rpc, network, lp)
	lp = finalizeRaydiumPermanentLPLock(lp)
	if lp.Available || lp.PoolProgram == meteoraDLMMProgram {
		lp = attachLiquidityMovementEvidence(ctx, lp)
		h.persistLiquidityMovementActorEvidence(ctx, network, mint, lp)
	}
	lp.EvidenceKeys = uniqueStrings(lp.EvidenceKeys)
	return lp
}

func resolveStreamflowLPTimeLock(ctx context.Context, rpc solanaRPCCall, network string, lp services.LPControlEvidence) services.LPControlEvidence {
	if lp.LockerAccount == "" || lp.LockerProgram != streamflowProgram || rpc == nil {
		return lp
	}
	var account rpcAccountInfoResponse
	if err := rpc(ctx, network, "getAccountInfo", []any{lp.LockerAccount, map[string]any{"encoding": "base64", "commitment": "confirmed"}}, &account); err != nil || account.Value == nil {
		lp.Limitations = append(lp.Limitations, "The Streamflow-owned account was observed, but its schedule account could not be read.")
		return lp
	}
	data, err := accountDataBytes(account.Value.Data)
	if err != nil {
		lp.Limitations = append(lp.Limitations, "The Streamflow-owned account was observed, but its schedule payload could not be decoded.")
		return lp
	}
	if unlock, ok := conservativeStreamflowUnlock(data, time.Now().UTC()); ok {
		lp.LockedUntil = &unlock
		lp.Status = services.LPControlVerifiedLocked
		lp.ReasonCode = "streamflow_schedule_observed"
		if account.Context.Slot > lp.ReadSlot {
			lp.ReadSlot = account.Context.Slot
		}
		lp.EvidenceKeys = append(lp.EvidenceKeys, fmt.Sprintf("locker:%s@%d", lp.LockerAccount, account.Context.Slot))
	}
	return lp
}

func collectRaydiumAMMV4Evidence(ctx context.Context, rpc solanaRPCCall, network, mint, creator, pool string) services.LPControlEvidence {
	out := services.LPControlEvidence{
		Status: services.LPControlUnverified, ReasonCode: "amm_v4_collection_incomplete",
		PoolAddress: pool, PoolProgram: raydiumAMMV4Program, PoolType: "raydium_amm_v4",
		ControlModel: "lp_token", PositionModel: "fungible_lp_token", TokenMint: mint, CreatorWallet: strings.TrimSpace(creator),
		ObservedAt: time.Now().UTC(), LargestLPHolders: []services.LPHolderEvidence{}, LockedLPTokenAccounts: []string{},
		LiquidityMovements: []services.LiquidityMovementEvidence{}, EvidenceKeys: []string{}, Limitations: []string{},
	}
	if rpc == nil || pool == "" {
		out.Status = services.LPControlSourceUnavailable
		return out
	}
	var account rpcAccountInfoResponse
	if err := rpc(ctx, network, "getAccountInfo", []any{pool, map[string]any{"encoding": "base64", "commitment": "confirmed"}}, &account); err != nil || account.Value == nil {
		out.Status, out.ReasonCode = services.LPControlSourceUnavailable, "amm_v4_pool_account_unavailable"
		out.Limitations = append(out.Limitations, compactCollectorError(err))
		return out
	}
	if strings.TrimSpace(account.Value.Owner) != raydiumAMMV4Program {
		out.ReasonCode = "amm_v4_program_owner_mismatch"
		out.Limitations = append(out.Limitations, "The pool account owner did not match the pinned Raydium AMM v4 program.")
		return out
	}
	data, err := accountDataBytes(account.Value.Data)
	if err != nil || len(data) < 496 {
		out.Status, out.ReasonCode = services.LPControlSourceUnavailable, "amm_v4_pool_state_short"
		out.Limitations = append(out.Limitations, compactCollectorError(err))
		return out
	}
	// Raydium LiquidityStateV4: fixed numeric region through byte 336, then
	// base vault, quote vault, base mint, quote mint and LP mint pubkeys.
	baseVault, quoteVault := base58Encode(data[336:368]), base58Encode(data[368:400])
	baseMint, quoteMint := base58Encode(data[400:432]), base58Encode(data[432:464])
	out.LPMint = base58Encode(data[464:496])
	out.ReadSlot = account.Context.Slot
	if baseMint == mint {
		out.TokenVault, out.QuoteVault, out.QuoteMint = baseVault, quoteVault, quoteMint
	} else if quoteMint == mint {
		out.TokenVault, out.QuoteVault, out.QuoteMint = quoteVault, baseVault, baseMint
	} else {
		out.ReasonCode = "amm_v4_pool_mint_mismatch"
		out.Limitations = append(out.Limitations, "The decoded AMM v4 pool mints did not contain the requested token.")
		return out
	}
	return populateDecodedLPControl(ctx, rpc, network, creator, out)
}

func populateDecodedLPControl(ctx context.Context, rpc solanaRPCCall, network, creator string, out services.LPControlEvidence) services.LPControlEvidence {
	if out.ControlModel == "" {
		out.ControlModel = "lp_token"
	}
	if out.PositionModel == "" {
		out.PositionModel = "fungible_lp_token"
	}
	if out.LockedLPTokenAccounts == nil {
		out.LockedLPTokenAccounts = []string{}
	}
	out.LPSupplySource = "mint_supply"
	var tokenReserve, quoteReserve rpcTokenBalanceResponse
	if err := rpc(ctx, network, "getTokenAccountBalance", []any{out.TokenVault, map[string]any{"commitment": "confirmed"}}, &tokenReserve); err == nil {
		out.TokenReserve = tokenReserve.Value.number()
		if tokenReserve.Context.Slot > out.ReadSlot {
			out.ReadSlot = tokenReserve.Context.Slot
		}
	} else {
		out.Limitations = append(out.Limitations, "The token vault reserve could not be read.")
	}
	if err := rpc(ctx, network, "getTokenAccountBalance", []any{out.QuoteVault, map[string]any{"commitment": "confirmed"}}, &quoteReserve); err == nil {
		out.QuoteReserve = quoteReserve.Value.number()
		out.EffectiveQuoteReserve = out.QuoteReserve
		if quoteReserve.Context.Slot > out.ReadSlot {
			out.ReadSlot = quoteReserve.Context.Slot
		}
	} else {
		out.Limitations = append(out.Limitations, "The quote vault reserve could not be read.")
	}
	var supply rpcTokenSupplyResponse
	if err := rpc(ctx, network, "getTokenSupply", []any{out.LPMint, map[string]any{"commitment": "confirmed"}}, &supply); err != nil {
		out.Status, out.ReasonCode = services.LPControlSourceUnavailable, "lp_supply_unavailable"
		out.Limitations = append(out.Limitations, compactCollectorError(err))
		return out
	}
	out.LPSupply = supply.Value.number()
	if supply.Context.Slot > out.ReadSlot {
		out.ReadSlot = supply.Context.Slot
	}
	var largest rpcLargestAccountsResponse
	if err := rpc(ctx, network, "getTokenLargestAccounts", []any{out.LPMint, map[string]any{"commitment": "confirmed"}}, &largest); err != nil {
		out.Status, out.ReasonCode = services.LPControlSourceUnavailable, "lp_holders_unavailable"
		out.Limitations = append(out.Limitations, compactCollectorError(err))
		return out
	}
	addresses := make([]string, 0, len(largest.Value))
	for _, item := range largest.Value {
		addresses = append(addresses, item.Address)
	}
	owners := resolveTokenAccountOwners(ctx, rpc, network, addresses)
	ownerPrograms := resolveAccountPrograms(ctx, rpc, network, uniqueStrings(mapValues(owners)))
	burnedAmount, creatorAmount := 0.0, 0.0
	for _, item := range largest.Value {
		amount := item.number()
		owner := strings.TrimSpace(owners[item.Address])
		program := strings.TrimSpace(ownerPrograms[owner])
		classification := "holder"
		if burnOwnerWallets[owner] || burnOwnerWallets[item.Address] {
			classification = "burn_address"
			burnedAmount += amount
		}
		if owner != "" && owner == strings.TrimSpace(creator) {
			classification = "creator"
			creatorAmount += amount
		}
		if label, ok := knownLPLockerPrograms[program]; ok {
			classification = label
			out.LockerProgram, out.LockerAccount = program, owner
		}
		share := 0.0
		if out.LPSupply > 0 {
			share = amount / out.LPSupply * 100
		}
		out.LargestLPHolders = append(out.LargestLPHolders, services.LPHolderEvidence{TokenAccount: item.Address, OwnerWallet: owner, Amount: amount, SharePct: roundCollectorPct(share), AccountOwner: program, Classification: classification})
	}
	if out.LPSupply > 0 {
		out.BurnedSharePct = roundCollectorPct(burnedAmount / out.LPSupply * 100)
		out.CreatorLPSharePct = roundCollectorPct(creatorAmount / out.LPSupply * 100)
	}
	out = summarizeLPControlOwnership(out, creator)
	out.Available = true
	out.Status = services.LPControlUnverified
	out.ReasonCode = "lp_control_not_proven"
	if out.BurnedSharePct > 0 {
		out.Status = services.LPControlVerifiedBurned
		out.ReasonCode = "burn_address_lp_observed"
	} else if out.LockerProgram != "" {
		out.ReasonCode = "locker_program_observed_unlock_unresolved"
	} else if out.CreatorLPSharePct > 0 {
		out.Status = services.LPControlHeldByCreator
		out.ReasonCode = "creator_owned_lp_observed"
	}
	out.EvidenceKeys = append(out.EvidenceKeys, fmt.Sprintf("pool:%s@%d", out.PoolAddress, out.ReadSlot), fmt.Sprintf("lp_mint:%s@%d", out.LPMint, out.ReadSlot), fmt.Sprintf("vault:%s@%d", out.TokenVault, out.ReadSlot), fmt.Sprintf("vault:%s@%d", out.QuoteVault, out.ReadSlot))
	return out
}

// conservativeStreamflowUnlock intentionally avoids guessing a lock timestamp.
// A value is accepted only when at least two aligned plausible schedule times
// (such as start/cliff/end) are present.
func conservativeStreamflowUnlock(data []byte, now time.Time) (time.Time, bool) {
	if len(data) < 24 {
		return time.Time{}, false
	}
	lower := now.Add(-10 * 365 * 24 * time.Hour).Unix()
	upper := now.Add(20 * 365 * 24 * time.Hour).Unix()
	future := now.Add(time.Minute).Unix()
	plausible := make([]int64, 0, 4)
	for offset := 0; offset+8 <= len(data); offset += 8 {
		value := int64(binary.LittleEndian.Uint64(data[offset : offset+8]))
		if value >= lower && value <= upper {
			plausible = append(plausible, value)
		}
	}
	if len(plausible) < 2 {
		return time.Time{}, false
	}
	latest := int64(0)
	for _, value := range plausible {
		if value > latest {
			latest = value
		}
	}
	if latest < future {
		return time.Time{}, false
	}
	return time.Unix(latest, 0).UTC(), true
}

// Compile-time guard for the JSON account type used by mocked and live RPC.
var _ = json.RawMessage{}
