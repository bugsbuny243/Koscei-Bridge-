package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"koschei/api/internal/services"
)

const (
	raydiumCLMMProgram          = "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK"
	raydiumCLMMLockAuthority    = "kN1kEznaF5Xbd8LYuqtEFcxzWSBk5Fv6ygX6SqEGJVy"
	raydiumCLMMLockAccountSize  = 241
	raydiumCLMMPositionSize     = 281
	raydiumCLMMLockResultLimit  = 200
	clmmSPLTokenProgram         = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	clmmSPLToken2022Program     = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
)

type raydiumCLMMLockCandidate struct {
	LockAccount      string
	PositionOwner    string
	PoolID           string
	PositionID       string
	LockedNFTAccount string
	FeeNFTMint       string
	RecentEpoch      uint64
	ReadSlot         uint64
}

type rpcProgramAccountsContextResponse struct {
	Context rpcContext `json:"context"`
	Value   []struct {
		Pubkey  string `json:"pubkey"`
		Account struct {
			Owner string `json:"owner"`
			Data  any    `json:"data"`
		} `json:"account"`
	} `json:"value"`
}

type clmmFetchedAccount struct {
	Owner    string
	Data     any
	ReadSlot uint64
}

// decodeRaydiumCLMMLPControl decodes the official CLMM PoolState and performs
// one pool-filtered, data-size-filtered Burn & Earn lock-state query. It never
// treats the pool's active-tick liquidity as a total-position denominator.
func decodeRaydiumCLMMLPControl(ctx context.Context, rpc solanaRPCCall, network string, out services.LPControlEvidence, data []byte) services.LPControlEvidence {
	out.PoolType = "raydium_clmm"
	out.ControlModel = "position_nft"
	out.PositionModel = "raydium_clmm_position_nft"
	out.LockerProgram = raydiumLPLockProgram
	out.PositionEnumerationLimit = raydiumCLMMLockResultLimit
	out.LockedPositions = []services.CLMMLockedPositionEvidence{}
	out.LockedLPTokenAccounts = []string{}
	out.LockedLPAuthorityAccounts = []string{}

	if len(data) < 253 || !anchorAccountDiscriminatorMatches(data, "PoolState") {
		out.Status, out.ReasonCode = services.LPControlSourceUnavailable, "raydium_clmm_pool_state_invalid"
		out.Limitations = append(out.Limitations, "The Raydium CLMM pool account did not match the pinned PoolState discriminator and minimum layout.")
		return out
	}
	out.PoolCreator = base58Encode(data[41:73])
	mintA, mintB := base58Encode(data[73:105]), base58Encode(data[105:137])
	vaultA, vaultB := base58Encode(data[137:169]), base58Encode(data[169:201])
	if mintA == out.TokenMint {
		out.TokenVault, out.QuoteVault, out.QuoteMint = vaultA, vaultB, mintB
	} else if mintB == out.TokenMint {
		out.TokenVault, out.QuoteVault, out.QuoteMint = vaultB, vaultA, mintA
	} else {
		out.Status, out.ReasonCode = services.LPControlUnverified, "raydium_clmm_pool_mint_mismatch"
		out.Limitations = append(out.Limitations, "The decoded Raydium CLMM pool mints did not contain the requested token.")
		return out
	}
	out.PoolLiquidityRaw = unsignedLittleEndian128(data[237:253]).String()
	out = populatePositionPoolReserves(ctx, rpc, network, out)
	out.Available = true
	out.Status = services.LPControlUnverified
	out.ReasonCode = "raydium_clmm_locked_positions_not_observed"
	out.PositionEnumerationStatus = "pending"
	out.EvidenceKeys = append(out.EvidenceKeys,
		fmt.Sprintf("pool:%s@%d", out.PoolAddress, out.ReadSlot),
		fmt.Sprintf("vault:%s@%d", out.TokenVault, out.ReadSlot),
		fmt.Sprintf("vault:%s@%d", out.QuoteVault, out.ReadSlot),
		"raydium_clmm_active_liquidity_raw:"+out.PoolLiquidityRaw,
	)
	out.Limitations = append(out.Limitations, "Raydium CLMM PoolState liquidity is active-tick liquidity, not the sum of all position liquidity; no locked percentage is calculated from it.")
	return collectRaydiumCLMMLockedPositions(ctx, rpc, network, out)
}

func collectRaydiumCLMMLockedPositions(ctx context.Context, rpc solanaRPCCall, network string, out services.LPControlEvidence) services.LPControlEvidence {
	if rpc == nil {
		out.PositionEnumerationStatus = "source_unavailable"
		out.ReasonCode = "raydium_clmm_lock_index_unavailable"
		out.Limitations = append(out.Limitations, "The Raydium CLMM Burn & Earn position index could not be queried.")
		return out
	}
	var response rpcProgramAccountsContextResponse
	config := map[string]any{
		"encoding":   "base64",
		"commitment": "confirmed",
		"withContext": true,
		"dataSlice": map[string]any{"offset": 0, "length": 177},
		"filters": []any{
			map[string]any{"dataSize": raydiumCLMMLockAccountSize},
			map[string]any{"memcmp": map[string]any{"offset": 41, "bytes": out.PoolAddress}},
		},
	}
	if out.ReadSlot > 0 {
		config["minContextSlot"] = out.ReadSlot
	}
	if err := rpc(ctx, network, "getProgramAccounts", []any{raydiumLPLockProgram, config}, &response); err != nil {
		out.PositionEnumerationStatus = "source_unavailable"
		out.ReasonCode = "raydium_clmm_lock_index_unavailable"
		out.Limitations = append(out.Limitations, compactCollectorError(err))
		return out
	}
	if out.ReadSlot > 0 && response.Context.Slot < out.ReadSlot {
		out.PositionEnumerationStatus = "source_unavailable"
		out.ReasonCode = "raydium_clmm_lock_context_stale"
		out.Limitations = append(out.Limitations, "The Raydium CLMM lock index response was older than the already observed pool evidence and was withheld.")
		return out
	}
	if response.Context.Slot > out.ReadSlot {
		out.ReadSlot = response.Context.Slot
	}
	if len(response.Value) > raydiumCLMMLockResultLimit {
		out.PositionEnumerationStatus = "limit_exceeded"
		out.ReasonCode = "raydium_clmm_lock_index_exceeds_limit"
		out.Limitations = append(out.Limitations, fmt.Sprintf("The pool-filtered Raydium CLMM lock index returned more than %d records; position evidence was withheld rather than truncated.", raydiumCLMMLockResultLimit))
		return out
	}
	if len(response.Value) == 0 {
		out.PositionEnumerationStatus = "complete_no_matches"
		out.ReasonCode = "raydium_clmm_no_current_locked_positions_observed"
		out.Limitations = append(out.Limitations, "No current Burn & Earn CLMM lock-state account matched this pool at the reported RPC context; this is not a historical unlock claim.")
		return out
	}

	candidates := make([]raydiumCLMMLockCandidate, 0, len(response.Value))
	invalidLockRecords := 0
	for _, entry := range response.Value {
		data, err := accountDataBytes(entry.Account.Data)
		if err != nil || strings.TrimSpace(entry.Account.Owner) != raydiumLPLockProgram || len(data) != 177 || !anchorAccountDiscriminatorMatches(data, "LockedClmmPositionState") {
			invalidLockRecords++
			continue
		}
		candidate := raydiumCLMMLockCandidate{
			LockAccount: strings.TrimSpace(entry.Pubkey),
			PositionOwner: base58Encode(data[9:41]),
			PoolID: base58Encode(data[41:73]),
			PositionID: base58Encode(data[73:105]),
			LockedNFTAccount: base58Encode(data[105:137]),
			FeeNFTMint: base58Encode(data[137:169]),
			RecentEpoch: binary.LittleEndian.Uint64(data[169:177]),
			ReadSlot: response.Context.Slot,
		}
		if candidate.LockAccount == "" || candidate.PoolID != out.PoolAddress || isDefaultSolanaAddress(candidate.PositionOwner) || isDefaultSolanaAddress(candidate.PositionID) || isDefaultSolanaAddress(candidate.LockedNFTAccount) || isDefaultSolanaAddress(candidate.FeeNFTMint) {
			invalidLockRecords++
			continue
		}
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		out.PositionEnumerationStatus = "unverified_records"
		out.ReasonCode = "raydium_clmm_lock_records_unverified"
		out.Limitations = append(out.Limitations, "Burn & Earn program accounts were returned for the pool, but none passed the pinned lock-state layout and identity checks.")
		return out
	}

	positionIDs := make([]string, 0, len(candidates))
	lockedNFTAccounts := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		positionIDs = append(positionIDs, candidate.PositionID)
		lockedNFTAccounts = append(lockedNFTAccounts, candidate.LockedNFTAccount)
	}
	positions, positionSlot, err := fetchCLMMAccountsInBatches(ctx, rpc, network, positionIDs, "base64", out.ReadSlot)
	if err != nil {
		out.PositionEnumerationStatus = "source_unavailable"
		out.ReasonCode = "raydium_clmm_positions_unavailable"
		out.Limitations = append(out.Limitations, compactCollectorError(err))
		return out
	}
	if positionSlot > out.ReadSlot {
		out.ReadSlot = positionSlot
	}
	custodyAccounts, custodySlot, err := fetchCLMMAccountsInBatches(ctx, rpc, network, lockedNFTAccounts, "jsonParsed", out.ReadSlot)
	if err != nil {
		out.PositionEnumerationStatus = "source_unavailable"
		out.ReasonCode = "raydium_clmm_custody_accounts_unavailable"
		out.Limitations = append(out.Limitations, compactCollectorError(err))
		return out
	}
	if custodySlot > out.ReadSlot {
		out.ReadSlot = custodySlot
	}

	totalLockedLiquidity := new(big.Int)
	invalidEvidence := invalidLockRecords
	for _, candidate := range candidates {
		positionAccount, positionOK := positions[candidate.PositionID]
		custodyAccount, custodyOK := custodyAccounts[candidate.LockedNFTAccount]
		if !positionOK || !custodyOK || strings.TrimSpace(positionAccount.Owner) != raydiumCLMMProgram {
			invalidEvidence++
			continue
		}
		positionData, err := accountDataBytes(positionAccount.Data)
		if err != nil || len(positionData) != raydiumCLMMPositionSize || !anchorAccountDiscriminatorMatches(positionData, "PersonalPositionState") {
			invalidEvidence++
			continue
		}
		positionNFTMint := base58Encode(positionData[9:41])
		positionPool := base58Encode(positionData[41:73])
		liquidity := unsignedLittleEndian128(positionData[81:97])
		if positionPool != out.PoolAddress || isDefaultSolanaAddress(positionNFTMint) || liquidity.Sign() <= 0 {
			invalidEvidence++
			continue
		}
		if !verifiedCLMMCustodyTokenAccount(custodyAccount, positionNFTMint) {
			invalidEvidence++
			continue
		}
		tickLower := int32(binary.LittleEndian.Uint32(positionData[73:77]))
		tickUpper := int32(binary.LittleEndian.Uint32(positionData[77:81]))
		if tickLower >= tickUpper {
			invalidEvidence++
			continue
		}
		totalLockedLiquidity.Add(totalLockedLiquidity, liquidity)
		evidenceKeys := []string{
			fmt.Sprintf("raydium_clmm_lock:%s@%d", candidate.LockAccount, candidate.ReadSlot),
			fmt.Sprintf("raydium_clmm_position:%s:%s@%d", candidate.PositionID, liquidity.String(), positionAccount.ReadSlot),
			fmt.Sprintf("raydium_clmm_custody:%s:%s@%d", candidate.LockedNFTAccount, positionNFTMint, custodyAccount.ReadSlot),
		}
		out.LockedPositions = append(out.LockedPositions, services.CLMMLockedPositionEvidence{
			LockedPositionAccount: candidate.LockAccount,
			PositionOwner: candidate.PositionOwner,
			PositionAccount: candidate.PositionID,
			PositionNFTMint: positionNFTMint,
			LockedNFTAccount: candidate.LockedNFTAccount,
			CustodyAuthority: raydiumCLMMLockAuthority,
			FeeNFTMint: candidate.FeeNFTMint,
			TickLowerIndex: tickLower,
			TickUpperIndex: tickUpper,
			LiquidityRaw: liquidity.String(),
			RecentEpoch: candidate.RecentEpoch,
			ReadSlot: maxCLMMReadSlot(candidate.ReadSlot, positionAccount.ReadSlot, custodyAccount.ReadSlot),
			VerificationStatus: "VERIFIED",
			EvidenceKeys: evidenceKeys,
		})
		out.EvidenceKeys = append(out.EvidenceKeys, evidenceKeys...)
	}

	out.LockedPositionCount = len(out.LockedPositions)
	out.LockedPositionLiquidityRaw = totalLockedLiquidity.String()
	out.EvidenceKeys = uniqueStrings(out.EvidenceKeys)
	if out.LockedPositionCount == 0 {
		out.PositionEnumerationStatus = "unverified_records"
		out.ReasonCode = "raydium_clmm_position_custody_unverified"
		out.Limitations = append(out.Limitations, "Current lock-state records were observed, but no lock-state, personal-position and NFT-custody chain passed every owner, pool, mint, amount and authority check.")
		return out
	}

	out.Status = services.LPControlVerifiedPermanentLocked
	out.ReasonCode = "raydium_clmm_burn_and_earn_positions_verified"
	out.LockerProgram = raydiumLPLockProgram
	out.LockerAccount = raydiumCLMMLockAuthority
	out.PositionEnumerationStatus = "verified_complete_bounded_filter"
	if invalidEvidence > 0 {
		out.PositionEnumerationStatus = "verified_partial_bounded_filter"
		out.Limitations = append(out.Limitations, fmt.Sprintf("%d returned CLMM lock records or linked accounts failed verification and were excluded; only listed VERIFIED positions contribute to locked liquidity.", invalidEvidence))
	}
	out.Limitations = append(out.Limitations,
		"Locked CLMM liquidity is the sum of verified position-state liquidity integers. It is not converted to a pool percentage because CLMM PoolState liquidity is active-tick liquidity rather than total position liquidity.",
		fmt.Sprintf("The lock query was restricted to the pinned Burn & Earn program, exact account size and this pool, with a fail-closed limit of %d current records.", raydiumCLMMLockResultLimit),
		"Linked position and custody reads were required to come from monotonically non-decreasing RPC contexts using minContextSlot; each custody edge retains its exact response slot.",
	)
	out.Limitations = uniqueStrings(out.Limitations)
	return out
}

func fetchCLMMAccountsInBatches(ctx context.Context, rpc solanaRPCCall, network string, addresses []string, encoding string, minContextSlot uint64) (map[string]clmmFetchedAccount, uint64, error) {
	addresses = uniqueStrings(addresses)
	out := make(map[string]clmmFetchedAccount, len(addresses))
	latestSlot := minContextSlot
	for start := 0; start < len(addresses); start += 100 {
		end := start + 100
		if end > len(addresses) {
			end = len(addresses)
		}
		batch := addresses[start:end]
		var response struct {
			Context rpcContext        `json:"context"`
			Value   []json.RawMessage `json:"value"`
		}
		config := map[string]any{"encoding": encoding, "commitment": "confirmed"}
		if latestSlot > 0 {
			config["minContextSlot"] = latestSlot
		}
		if err := rpc(ctx, network, "getMultipleAccounts", []any{batch, config}, &response); err != nil {
			return nil, 0, err
		}
		if latestSlot > 0 && response.Context.Slot < latestSlot {
			return nil, 0, errors.New("getMultipleAccounts returned a stale CLMM context")
		}
		if response.Context.Slot > latestSlot {
			latestSlot = response.Context.Slot
		}
		if len(response.Value) != len(batch) {
			return nil, 0, errors.New("getMultipleAccounts returned an incomplete CLMM batch")
		}
		for index, raw := range response.Value {
			if len(raw) == 0 || string(raw) == "null" {
				continue
			}
			var account struct {
				Owner string `json:"owner"`
				Data  any    `json:"data"`
			}
			if json.Unmarshal(raw, &account) != nil {
				continue
			}
			out[batch[index]] = clmmFetchedAccount{
				Owner: strings.TrimSpace(account.Owner),
				Data: account.Data,
				ReadSlot: response.Context.Slot,
			}
		}
	}
	return out, latestSlot, nil
}

func verifiedCLMMCustodyTokenAccount(account clmmFetchedAccount, expectedMint string) bool {
	ownerProgram := strings.TrimSpace(account.Owner)
	if ownerProgram != clmmSPLTokenProgram && ownerProgram != clmmSPLToken2022Program {
		return false
	}
	raw, _ := json.Marshal(account.Data)
	var parsed struct {
		Parsed struct {
			Info struct {
				Mint        string `json:"mint"`
				Owner       string `json:"owner"`
				TokenAmount struct {
					Amount   string `json:"amount"`
					Decimals int    `json:"decimals"`
				} `json:"tokenAmount"`
			} `json:"info"`
		} `json:"parsed"`
	}
	if json.Unmarshal(raw, &parsed) != nil {
		return false
	}
	amount, err := strconv.ParseUint(strings.TrimSpace(parsed.Parsed.Info.TokenAmount.Amount), 10, 64)
	return err == nil && amount == 1 && parsed.Parsed.Info.TokenAmount.Decimals == 0 &&
		strings.TrimSpace(parsed.Parsed.Info.Mint) == strings.TrimSpace(expectedMint) &&
		strings.TrimSpace(parsed.Parsed.Info.Owner) == raydiumCLMMLockAuthority
}

func anchorAccountDiscriminatorMatches(data []byte, accountName string) bool {
	if len(data) < 8 || strings.TrimSpace(accountName) == "" {
		return false
	}
	digest := sha256.Sum256([]byte("account:" + strings.TrimSpace(accountName)))
	return bytes.Equal(data[:8], digest[:8])
}

func isDefaultSolanaAddress(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || value == "11111111111111111111111111111111"
}

func maxCLMMReadSlot(values ...uint64) uint64 {
	var maximum uint64
	for _, value := range values {
		if value > maximum {
			maximum = value
		}
	}
	return maximum
}
