package handlers

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const (
	pumpSwapProgram      = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"
	meteoraDAMMV2Program = "cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG"
	meteoraDLMMProgram   = "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo"
)

func collectProtocolLPControlEvidence(ctx context.Context, rpc solanaRPCCall, network, mint, creator, pool string) services.LPControlEvidence {
	out := services.LPControlEvidence{
		Status: services.LPControlUnverified, PoolAddress: strings.TrimSpace(pool), TokenMint: strings.TrimSpace(mint),
		CreatorWallet: strings.TrimSpace(creator),
		ObservedAt:    time.Now().UTC(), LargestLPHolders: []services.LPHolderEvidence{},
		LockedPositions: []services.CLMMLockedPositionEvidence{},
		LiquidityMovements: []services.LiquidityMovementEvidence{}, EvidenceKeys: []string{}, Limitations: []string{},
	}
	if rpc == nil || out.PoolAddress == "" {
		out.Status, out.ReasonCode = services.LPControlSourceUnavailable, "pool_account_unavailable"
		return out
	}
	var account rpcAccountInfoResponse
	if err := rpc(ctx, network, "getAccountInfo", []any{out.PoolAddress, map[string]any{"encoding": "base64", "commitment": "confirmed"}}, &account); err != nil || account.Value == nil {
		out.Status, out.ReasonCode = services.LPControlSourceUnavailable, "pool_account_unavailable"
		out.Limitations = append(out.Limitations, compactCollectorError(err))
		return out
	}
	out.PoolProgram, out.ReadSlot = strings.TrimSpace(account.Value.Owner), account.Context.Slot
	data, err := accountDataBytes(account.Value.Data)
	if err != nil {
		out.Status, out.ReasonCode = services.LPControlSourceUnavailable, "pool_account_decode_failed"
		out.Limitations = append(out.Limitations, compactCollectorError(err))
		return out
	}
	switch out.PoolProgram {
	case raydiumCLMMProgram:
		return decodeRaydiumCLMMLPControl(ctx, rpc, network, out, data)
	case pumpSwapProgram:
		return decodePumpSwapLPControl(ctx, rpc, network, creator, out, data)
	case meteoraDAMMV2Program:
		return decodeMeteoraDAMMV2LPControl(ctx, rpc, network, out, data)
	case meteoraDLMMProgram:
		return decodeMeteoraDLMMLPControl(ctx, rpc, network, out, data)
	default:
		out.ReasonCode = "unsupported_pool_program"
		out.Limitations = append(out.Limitations, "The observed pair account is not owned by a pinned Raydium, PumpSwap or Meteora pool program.")
		return out
	}
}

func decodePumpSwapLPControl(ctx context.Context, rpc solanaRPCCall, network, creator string, out services.LPControlEvidence, data []byte) services.LPControlEvidence {
	// Official PumpSwap Pool layout: discriminator(8), bump(1), index(2),
	// creator, base mint, quote mint, LP mint, base vault, quote vault,
	// circulating LP supply, coin creator, two booleans, virtual quote i128.
	if len(data) < 211 {
		out.Status, out.ReasonCode = services.LPControlSourceUnavailable, "pumpswap_pool_state_short"
		return out
	}
	index := binary.LittleEndian.Uint16(data[9:11])
	poolCreator := base58Encode(data[11:43])
	baseMint, quoteMint := base58Encode(data[43:75]), base58Encode(data[75:107])
	out.PoolType = "pumpswap_amm"
	out.ControlModel = "lp_token"
	out.PositionModel = "fungible_lp_token"
	out.PoolCreator = poolCreator
	out.CanonicalPool = index == 0
	out.LPMint = base58Encode(data[107:139])
	baseVault, quoteVault := base58Encode(data[139:171]), base58Encode(data[171:203])
	if baseMint == out.TokenMint {
		out.TokenVault, out.QuoteVault, out.QuoteMint = baseVault, quoteVault, quoteMint
	} else if quoteMint == out.TokenMint {
		out.TokenVault, out.QuoteVault, out.QuoteMint = quoteVault, baseVault, baseMint
	} else {
		out.ReasonCode = "pumpswap_pool_mint_mismatch"
		out.Limitations = append(out.Limitations, "The decoded PumpSwap pool mints did not contain the requested token.")
		return out
	}
	poolCirculatingLP := binary.LittleEndian.Uint64(data[203:211])
	out = populateDecodedLPControl(ctx, rpc, network, creator, out)
	out.LPSupplySource = "mint_supply"
	out.EvidenceKeys = append(out.EvidenceKeys, fmt.Sprintf("pumpswap_pool_index:%d", index), fmt.Sprintf("pumpswap_circulating_lp_raw:%d", poolCirculatingLP))
	if len(data) >= 261 {
		virtualRaw := signedLittleEndian128(data[245:261])
		if virtualRaw.Sign() > 0 {
			decimals := tokenMintDecimals(ctx, rpc, network, out.QuoteMint)
			out.VirtualQuoteReserve = scaleBigInteger(virtualRaw, decimals)
			out.EffectiveQuoteReserve = out.QuoteReserve + out.VirtualQuoteReserve
			out.EvidenceKeys = append(out.EvidenceKeys, "pumpswap_virtual_quote_reserve:"+virtualRaw.String())
		}
	}
	if out.EffectiveQuoteReserve == 0 {
		out.EffectiveQuoteReserve = out.QuoteReserve
	}
	if out.CanonicalPool && out.BurnedSharePct == 0 {
		out.Limitations = append(out.Limitations, "Canonical pool identity does not by itself prove the current LP burn share; the reported share comes only from resolved LP-token holders.")
	}
	return out
}

func decodeMeteoraDAMMV2LPControl(ctx context.Context, rpc solanaRPCCall, network string, out services.LPControlEvidence, data []byte) services.LPControlEvidence {
	// Official DAMM v2 Pool account order places token A/B mints and vaults after
	// the 160-byte PoolFees struct. The account uses position NFTs, not an LP mint.
	if len(data) < 568 {
		out.Status, out.ReasonCode = services.LPControlSourceUnavailable, "meteora_damm_v2_pool_state_short"
		return out
	}
	tokenAMint, tokenBMint := base58Encode(data[168:200]), base58Encode(data[200:232])
	vaultA, vaultB := base58Encode(data[232:264]), base58Encode(data[264:296])
	out.PoolType = "meteora_damm_v2"
	out.ControlModel = "position_nft"
	out.PositionModel = "meteora_damm_v2_position_nft"
	if tokenAMint == out.TokenMint {
		out.TokenVault, out.QuoteVault, out.QuoteMint = vaultA, vaultB, tokenBMint
	} else if tokenBMint == out.TokenMint {
		out.TokenVault, out.QuoteVault, out.QuoteMint = vaultB, vaultA, tokenAMint
	} else {
		out.ReasonCode = "meteora_damm_v2_pool_mint_mismatch"
		out.Limitations = append(out.Limitations, "The decoded Meteora DAMM v2 pool mints did not contain the requested token.")
		return out
	}
	liquidity := unsignedLittleEndian128(data[360:376])
	permanentLocked := unsignedLittleEndian128(data[552:568])
	out.PoolLiquidityRaw = liquidity.String()
	out.PermanentLockedLiquidityRaw = permanentLocked.String()
	if liquidity.Sign() > 0 {
		ratio, _ := new(big.Rat).SetFrac(permanentLocked, liquidity).Float64()
		out.PermanentLockedSharePct = roundCollectorPct(math.Min(100, math.Max(0, ratio*100)))
	}
	out = populatePositionPoolReserves(ctx, rpc, network, out)
	out.Available = true
	out.Status, out.ReasonCode = services.LPControlUnverified, "position_ownership_not_enumerated"
	if permanentLocked.Sign() > 0 {
		out.Status, out.ReasonCode = services.LPControlVerifiedPermanentLocked, "meteora_permanent_lock_observed"
	}
	out.EvidenceKeys = append(out.EvidenceKeys,
		fmt.Sprintf("pool:%s@%d", out.PoolAddress, out.ReadSlot),
		fmt.Sprintf("vault:%s@%d", out.TokenVault, out.ReadSlot),
		fmt.Sprintf("vault:%s@%d", out.QuoteVault, out.ReadSlot),
		"meteora_pool_liquidity_raw:"+liquidity.String(),
		"meteora_permanent_lock_raw:"+permanentLocked.String(),
	)
	out.Limitations = append(out.Limitations, "Meteora DAMM v2 liquidity ownership is position-NFT based. No LP-token supply, burn percentage or creator LP share is inferred for this pool model.")
	return out
}

func decodeMeteoraDLMMLPControl(ctx context.Context, rpc solanaRPCCall, network string, out services.LPControlEvidence, data []byte) services.LPControlEvidence {
	// Official DLMM LbPair is a bytemuck C-layout account. After the 8-byte
	// discriminator: StaticParameters(32), VariableParameters(32), seeds/status
	// fields(16), then token X/Y mints and reserve X/Y vaults.
	if len(data) < 216 {
		out.Status, out.ReasonCode = services.LPControlSourceUnavailable, "meteora_dlmm_pool_state_short"
		return out
	}
	tokenXMint, tokenYMint := base58Encode(data[88:120]), base58Encode(data[120:152])
	reserveX, reserveY := base58Encode(data[152:184]), base58Encode(data[184:216])
	out.PoolType = "meteora_dlmm"
	out.ControlModel = "position_nft"
	out.PositionModel = "meteora_dlmm_position"
	if tokenXMint == out.TokenMint {
		out.TokenVault, out.QuoteVault, out.QuoteMint = reserveX, reserveY, tokenYMint
	} else if tokenYMint == out.TokenMint {
		out.TokenVault, out.QuoteVault, out.QuoteMint = reserveY, reserveX, tokenXMint
	} else {
		out.ReasonCode = "meteora_dlmm_pool_mint_mismatch"
		out.Limitations = append(out.Limitations, "The decoded Meteora DLMM pair mints did not contain the requested token.")
		return out
	}
	out = populatePositionPoolReserves(ctx, rpc, network, out)
	out.Available = true
	out.Status = services.LPControlUnverified
	out.ReasonCode = "dlmm_position_ownership_not_enumerated"
	out.EvidenceKeys = append(out.EvidenceKeys,
		fmt.Sprintf("pool:%s@%d", out.PoolAddress, out.ReadSlot),
		fmt.Sprintf("vault:%s@%d", out.TokenVault, out.ReadSlot),
		fmt.Sprintf("vault:%s@%d", out.QuoteVault, out.ReadSlot),
	)
	out.Limitations = append(out.Limitations, "Meteora DLMM liquidity ownership is position-account based. Pool mint and vault offsets are decoded from the pinned bytemuck layout, but position owners are not inferred from the pool account.")
	return out
}

func populatePositionPoolReserves(ctx context.Context, rpc solanaRPCCall, network string, out services.LPControlEvidence) services.LPControlEvidence {
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
	return out
}

func tokenMintDecimals(ctx context.Context, rpc solanaRPCCall, network, mint string) int {
	if rpc == nil || strings.TrimSpace(mint) == "" {
		return 0
	}
	var supply rpcTokenSupplyResponse
	if rpc(ctx, network, "getTokenSupply", []any{mint, map[string]any{"commitment": "confirmed"}}, &supply) != nil {
		return 0
	}
	return supply.Value.Decimals
}

func unsignedLittleEndian128(data []byte) *big.Int {
	if len(data) < 16 {
		return new(big.Int)
	}
	reversed := make([]byte, 16)
	for i := 0; i < 16; i++ {
		reversed[15-i] = data[i]
	}
	return new(big.Int).SetBytes(reversed)
}

func signedLittleEndian128(data []byte) *big.Int {
	value := unsignedLittleEndian128(data)
	if len(data) >= 16 && data[15]&0x80 != 0 {
		value.Sub(value, new(big.Int).Lsh(big.NewInt(1), 128))
	}
	return value
}

func scaleBigInteger(value *big.Int, decimals int) float64 {
	if value == nil || value.Sign() <= 0 {
		return 0
	}
	denominator := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	result, _ := new(big.Rat).SetFrac(value, denominator).Float64()
	return creatorIntelRound(result, 8)
}
