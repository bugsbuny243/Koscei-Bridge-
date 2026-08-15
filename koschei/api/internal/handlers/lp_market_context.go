package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const (
	raydiumCPMMProgram     = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C"
	raydiumAMMV4Program    = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"
	raydiumLPLockProgram   = "LockrWmn6K5twhz3y9w1dQERbmgSaRkfnTeTKbpofwE"
	streamflowProgram      = "strmRqUCoQUgGUan5YhzUZa6KqdzwX5L6FpUxfmKg5m"
	jupiterUSDCMint        = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
	defaultJupiterPriceURL = "https://api.jup.ag/price/v3"
	defaultJupiterQuoteURL = "https://api.jup.ag/swap/v1/quote"
)

var knownLPLockerPrograms = map[string]string{
	raydiumLPLockProgram: "raydium_burn_and_earn",
	streamflowProgram:    "streamflow",
}

var burnOwnerWallets = map[string]bool{
	"1nc1nerator11111111111111111111111111111111": true,
	"11111111111111111111111111111111":            true,
}

type solanaRPCCall func(context.Context, string, string, any, any) error

func (h *Handler) lpRPC() solanaRPCCall {
	return func(ctx context.Context, network, method string, params any, out any) error {
		return h.callSolanaRPC(ctx, &http.Client{Timeout: 10 * time.Second}, solanaRPCURL(network, os.Getenv("ALCHEMY_API_KEY")), network, method, params, out)
	}
}

func (h *Handler) collectLPControlEvidence(ctx context.Context, network, mint, creator string, market services.TokenMarketSnapshot, source map[string]any) services.LPControlEvidence {
	return collectLPControlEvidence(ctx, h.lpRPC(), network, mint, creator, market, source)
}

func collectLPControlEvidence(ctx context.Context, rpc solanaRPCCall, network, mint, creator string, market services.TokenMarketSnapshot, source map[string]any) services.LPControlEvidence {
	now := time.Now().UTC()
	out := services.LPControlEvidence{
		Status: services.LPControlUnverified, ObservedAt: now,
		CreatorWallet:    strings.TrimSpace(creator),
		LargestLPHolders: []services.LPHolderEvidence{}, EvidenceKeys: []string{}, Limitations: []string{},
	}
	mint = strings.TrimSpace(mint)
	pair := strings.TrimSpace(market.BestPairAddress)
	dex := strings.ToLower(strings.TrimSpace(market.BestPairDEX))
	launchPlatform := strings.ToLower(strings.TrimSpace(fmt.Sprint(source["launch_platform"])))
	if pair == "" {
		out.Status = services.LPControlNotApplicable
		out.ReasonCode = "bonding_curve_no_amm_pool"
		if !strings.Contains(launchPlatform, "pump") {
			out.ReasonCode = "no_amm_pool_observed"
		}
		out.Limitations = append(out.Limitations, "No AMM pool was observed for this scan snapshot.")
		return out
	}
	if !strings.Contains(dex, "raydium") {
		out.Status = services.LPControlNotApplicable
		out.ReasonCode = "primary_pool_not_raydium"
		out.PoolAddress = pair
		out.PoolType = market.BestPairDEX
		out.Limitations = append(out.Limitations, "The primary observed pool is not a Raydium pool; the Raydium LP collector is not applicable.")
		return out
	}
	if rpc == nil {
		out.Status = services.LPControlSourceUnavailable
		out.ReasonCode = "rpc_unavailable"
		return out
	}

	var account rpcAccountInfoResponse
	if err := rpc(ctx, network, "getAccountInfo", []any{pair, map[string]any{"encoding": "base64", "commitment": "confirmed"}}, &account); err != nil || account.Value == nil {
		out.Status = services.LPControlSourceUnavailable
		out.ReasonCode = "pool_account_unavailable"
		out.Limitations = append(out.Limitations, compactCollectorError(err))
		return out
	}
	out.PoolAddress = pair
	out.PoolProgram = strings.TrimSpace(account.Value.Owner)
	out.ReadSlot = account.Context.Slot
	data, err := accountDataBytes(account.Value.Data)
	if err != nil {
		out.Status = services.LPControlSourceUnavailable
		out.ReasonCode = "pool_account_decode_failed"
		out.Limitations = append(out.Limitations, compactCollectorError(err))
		return out
	}
	var token0Mint, token1Mint, vault0, vault1, lpMint string
	switch out.PoolProgram {
	case raydiumCPMMProgram:
		out.PoolType = "raydium_cpmm"
		if len(data) < 232 {
			out.Status = services.LPControlSourceUnavailable
			out.ReasonCode = "cpmm_pool_state_short"
			return out
		}
		out.PoolCreator = base58Encode(data[40:72])
		vault0 = base58Encode(data[72:104])
		vault1 = base58Encode(data[104:136])
		lpMint = base58Encode(data[136:168])
		token0Mint = base58Encode(data[168:200])
		token1Mint = base58Encode(data[200:232])
	case raydiumAMMV4Program:
		out.PoolType = "raydium_amm_v4"
		out.Status = services.LPControlUnverified
		out.ReasonCode = "amm_v4_layout_not_resolved"
		out.Limitations = append(out.Limitations, "The observed pool uses Raydium AMM v4; direct CPMM offsets were not applied to this legacy layout.")
		return out
	default:
		out.Status = services.LPControlUnverified
		out.ReasonCode = "unrecognized_raydium_pool_program"
		out.Limitations = append(out.Limitations, "The pair address was labelled Raydium by market context but its on-chain owner did not match a pinned Raydium pool program.")
		return out
	}
	out.LPMint = lpMint
	if token0Mint == mint {
		out.TokenVault, out.QuoteVault, out.QuoteMint = vault0, vault1, token1Mint
	} else if token1Mint == mint {
		out.TokenVault, out.QuoteVault, out.QuoteMint = vault1, vault0, token0Mint
	} else {
		out.Status = services.LPControlUnverified
		out.ReasonCode = "pool_mint_mismatch"
		out.Limitations = append(out.Limitations, "The decoded pool mints did not contain the requested token mint.")
		return out
	}

	var tokenReserve, quoteReserve rpcTokenBalanceResponse
	if err := rpc(ctx, network, "getTokenAccountBalance", []any{out.TokenVault, map[string]any{"commitment": "confirmed"}}, &tokenReserve); err == nil {
		out.TokenReserve = tokenReserve.Value.number()
		if tokenReserve.Context.Slot > out.ReadSlot {
			out.ReadSlot = tokenReserve.Context.Slot
		}
	}
	if err := rpc(ctx, network, "getTokenAccountBalance", []any{out.QuoteVault, map[string]any{"commitment": "confirmed"}}, &quoteReserve); err == nil {
		out.QuoteReserve = quoteReserve.Value.number()
		if quoteReserve.Context.Slot > out.ReadSlot {
			out.ReadSlot = quoteReserve.Context.Slot
		}
	}

	var supply rpcTokenSupplyResponse
	if err := rpc(ctx, network, "getTokenSupply", []any{lpMint, map[string]any{"commitment": "confirmed"}}, &supply); err != nil {
		out.Status = services.LPControlSourceUnavailable
		out.ReasonCode = "lp_supply_unavailable"
		out.Limitations = append(out.Limitations, compactCollectorError(err))
		return out
	}
	out.LPSupply = supply.Value.number()
	if supply.Context.Slot > out.ReadSlot {
		out.ReadSlot = supply.Context.Slot
	}

	var largest rpcLargestAccountsResponse
	if err := rpc(ctx, network, "getTokenLargestAccounts", []any{lpMint, map[string]any{"commitment": "confirmed"}}, &largest); err != nil {
		out.Status = services.LPControlSourceUnavailable
		out.ReasonCode = "lp_holders_unavailable"
		out.Limitations = append(out.Limitations, compactCollectorError(err))
		return out
	}
	addresses := make([]string, 0, len(largest.Value))
	for _, item := range largest.Value {
		addresses = append(addresses, item.Address)
	}
	owners := resolveTokenAccountOwners(ctx, rpc, network, addresses)
	ownerPrograms := resolveAccountPrograms(ctx, rpc, network, uniqueStrings(mapValues(owners)))
	burnedAmount := 0.0
	creatorAmount := 0.0
	lockerProgram, lockerAccount := "", ""
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
			lockerProgram, lockerAccount = program, owner
		}
		share := 0.0
		if out.LPSupply > 0 {
			share = amount / out.LPSupply * 100
		}
		out.LargestLPHolders = append(out.LargestLPHolders, services.LPHolderEvidence{
			TokenAccount: item.Address, OwnerWallet: owner, Amount: amount, SharePct: roundCollectorPct(share),
			AccountOwner: program, Classification: classification,
		})
	}
	if out.LPSupply > 0 {
		out.BurnedSharePct = roundCollectorPct(burnedAmount / out.LPSupply * 100)
		out.CreatorLPSharePct = roundCollectorPct(creatorAmount / out.LPSupply * 100)
	}
	out = summarizeLPControlOwnership(out, creator)
	out.LockerProgram, out.LockerAccount = lockerProgram, lockerAccount
	out.Available = true
	out.Status = services.LPControlUnverified
	out.ReasonCode = "lp_control_not_proven"
	if out.BurnedSharePct > 0 {
		out.Status = services.LPControlVerifiedBurned
		out.ReasonCode = "burn_address_lp_observed"
	} else if lockerProgram != "" {
		out.Status = services.LPControlUnverified
		out.ReasonCode = "locker_program_observed_unlock_unresolved"
		out.Limitations = append(out.Limitations, "A known locker-program-owned account was observed, but an unlock timestamp was not decoded; lock duration remains unverified.")
	} else if out.CreatorLPSharePct > 0 {
		out.Status = services.LPControlHeldByCreator
		out.ReasonCode = "creator_owned_lp_observed"
	}
	out.EvidenceKeys = append(out.EvidenceKeys,
		fmt.Sprintf("pool:%s@%d", out.PoolAddress, out.ReadSlot),
		fmt.Sprintf("lp_mint:%s@%d", out.LPMint, out.ReadSlot),
		fmt.Sprintf("vault:%s@%d", out.TokenVault, out.ReadSlot),
		fmt.Sprintf("vault:%s@%d", out.QuoteVault, out.ReadSlot),
	)
	return out
}

func summarizeLPControlOwnership(out services.LPControlEvidence, creator string) services.LPControlEvidence {
	for _, holder := range out.LargestLPHolders {
		if holder.SharePct <= out.DominantLPSharePct {
			continue
		}
		out.DominantLPOwner = holder.OwnerWallet
		out.DominantLPTokenAccount = holder.TokenAccount
		out.DominantLPSharePct = holder.SharePct
		out.DominantLPClassification = holder.Classification
	}
	creator = strings.TrimSpace(creator)
	switch {
	case creator != "" && strings.TrimSpace(out.PoolCreator) == creator:
		out.CreatorRelation = "verified_pool_creator"
	case creator != "" && out.CreatorLPSharePct > 0:
		out.CreatorRelation = "verified_current_lp_holder"
	case creator != "":
		out.CreatorRelation = "not_observed"
	default:
		out.CreatorRelation = "creator_unavailable"
	}
	return out
}

type rpcContext struct {
	Slot uint64 `json:"slot"`
}

type rpcAccountInfoResponse struct {
	Context rpcContext `json:"context"`
	Value   *struct {
		Owner string `json:"owner"`
		Data  any    `json:"data"`
	} `json:"value"`
}

type rpcTokenAmount struct {
	Amount         string  `json:"amount"`
	Decimals       int     `json:"decimals"`
	UIAmount       float64 `json:"uiAmount"`
	UIAmountString string  `json:"uiAmountString"`
}

func (v rpcTokenAmount) number() float64 {
	if v.UIAmountString != "" {
		n, _ := strconv.ParseFloat(v.UIAmountString, 64)
		return n
	}
	if v.UIAmount != 0 {
		return v.UIAmount
	}
	n, _ := strconv.ParseFloat(v.Amount, 64)
	return n / math.Pow10(v.Decimals)
}

type rpcTokenBalanceResponse struct {
	Context rpcContext     `json:"context"`
	Value   rpcTokenAmount `json:"value"`
}

type rpcTokenSupplyResponse = rpcTokenBalanceResponse

type rpcLargestAccount struct {
	Address string `json:"address"`
	rpcTokenAmount
}

func (v rpcLargestAccount) number() float64 { return v.rpcTokenAmount.number() }

type rpcLargestAccountsResponse struct {
	Context rpcContext          `json:"context"`
	Value   []rpcLargestAccount `json:"value"`
}

func resolveTokenAccountOwners(ctx context.Context, rpc solanaRPCCall, network string, addresses []string) map[string]string {
	out := map[string]string{}
	if len(addresses) == 0 {
		return out
	}
	var response struct {
		Value []json.RawMessage `json:"value"`
	}
	if rpc(ctx, network, "getMultipleAccounts", []any{addresses, map[string]any{"encoding": "jsonParsed", "commitment": "confirmed"}}, &response) != nil {
		return out
	}
	for i, raw := range response.Value {
		if i >= len(addresses) || len(raw) == 0 || string(raw) == "null" {
			continue
		}
		var value struct {
			Data struct {
				Parsed struct {
					Info struct {
						Owner string `json:"owner"`
					} `json:"info"`
				} `json:"parsed"`
			} `json:"data"`
		}
		if json.Unmarshal(raw, &value) == nil {
			out[addresses[i]] = strings.TrimSpace(value.Data.Parsed.Info.Owner)
		}
	}
	return out
}

func resolveAccountPrograms(ctx context.Context, rpc solanaRPCCall, network string, addresses []string) map[string]string {
	out := map[string]string{}
	if len(addresses) == 0 {
		return out
	}
	var response struct {
		Value []json.RawMessage `json:"value"`
	}
	if rpc(ctx, network, "getMultipleAccounts", []any{addresses, map[string]any{"encoding": "base64", "commitment": "confirmed"}}, &response) != nil {
		return out
	}
	for i, raw := range response.Value {
		if i >= len(addresses) || len(raw) == 0 || string(raw) == "null" {
			continue
		}
		var value struct {
			Owner string `json:"owner"`
		}
		if json.Unmarshal(raw, &value) == nil {
			out[addresses[i]] = strings.TrimSpace(value.Owner)
		}
	}
	return out
}

func accountDataBytes(value any) ([]byte, error) {
	raw, _ := json.Marshal(value)
	var pair []any
	if json.Unmarshal(raw, &pair) == nil && len(pair) > 0 {
		text, _ := pair[0].(string)
		return base64.StdEncoding.DecodeString(text)
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return base64.StdEncoding.DecodeString(text)
	}
	return nil, fmt.Errorf("unsupported account data")
}

func decimalToRaw(value float64, decimals int) string {
	if value <= 0 || decimals < 0 || decimals > 18 {
		return ""
	}
	raw := value * math.Pow10(decimals)
	if raw <= 0 || raw > math.MaxUint64 {
		return ""
	}
	return strconv.FormatUint(uint64(math.Floor(raw)), 10)
}

func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func roundCollectorPct(value float64) float64 { return math.Round(value*10000) / 10000 }

func compactCollectorError(err error) string {
	if err == nil {
		return ""
	}
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > 180 {
		s = s[:180]
	}
	return s
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}
	digits := []byte{0}
	for _, b := range input {
		carry := int(b)
		for j := 0; j < len(digits); j++ {
			carry += int(digits[j]) << 8
			digits[j] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, byte(carry%58))
			carry /= 58
		}
	}
	out := make([]byte, 0, zeros+len(digits))
	for i := 0; i < zeros; i++ {
		out = append(out, '1')
	}
	for i := len(digits) - 1; i >= 0; i-- {
		out = append(out, base58Alphabet[digits[i]])
	}
	return string(out)
}
