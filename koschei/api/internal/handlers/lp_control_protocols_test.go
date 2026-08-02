package handlers

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"koschei/api/internal/services"
)

func protocolTestKey(seed byte) ([]byte, string) {
	value := make([]byte, 32)
	for i := range value {
		value[i] = seed + byte(i%11)
	}
	return value, base58Encode(value)
}

func TestPumpSwapCollectorDecodesCanonicalPoolAndVirtualReserve(t *testing.T) {
	data := make([]byte, 261)
	data[8] = 7
	binary.LittleEndian.PutUint16(data[9:11], 0)
	creatorBytes, creator := protocolTestKey(3)
	copy(data[11:43], creatorBytes)
	baseBytes, mint := protocolTestKey(20)
	copy(data[43:75], baseBytes)
	quoteBytes, quoteMint := protocolTestKey(40)
	copy(data[75:107], quoteBytes)
	lpBytes, lpMint := protocolTestKey(60)
	copy(data[107:139], lpBytes)
	baseVaultBytes, baseVault := protocolTestKey(80)
	copy(data[139:171], baseVaultBytes)
	quoteVaultBytes, quoteVault := protocolTestKey(100)
	copy(data[171:203], quoteVaultBytes)
	binary.LittleEndian.PutUint64(data[203:211], 1000)
	copy(data[211:243], creatorBytes)
	binary.LittleEndian.PutUint64(data[245:253], 5_000_000)
	burnTokenAccount := "PumpBurnLPTokenAccount111111111111111111111"
	balanceCalls := 0
	rpc := func(_ context.Context, _ string, method string, params any, out any) error {
		switch method {
		case "getAccountInfo":
			response := out.(*rpcAccountInfoResponse)
			response.Context.Slot = 901
			response.Value = &struct {
				Owner string `json:"owner"`
				Data  any    `json:"data"`
			}{Owner: pumpSwapProgram, Data: []any{base64.StdEncoding.EncodeToString(data), "base64"}}
		case "getTokenAccountBalance":
			balanceCalls++
			response := out.(*rpcTokenBalanceResponse)
			response.Context.Slot = 902
			response.Value.Decimals = 6
			if balanceCalls == 1 {
				response.Value.UIAmountString = "2000"
			} else {
				response.Value.UIAmountString = "100"
			}
		case "getTokenSupply":
			response := out.(*rpcTokenSupplyResponse)
			response.Context.Slot = 903
			args := params.([]any)
			if args[0] == quoteMint {
				response.Value.Decimals = 6
				response.Value.UIAmountString = "1000000"
			} else {
				response.Value.Decimals = 6
				response.Value.UIAmountString = "1000"
			}
		case "getTokenLargestAccounts":
			response := out.(*rpcLargestAccountsResponse)
			response.Context.Slot = 903
			response.Value = []rpcLargestAccount{{Address: burnTokenAccount, rpcTokenAmount: rpcTokenAmount{UIAmountString: "900", Decimals: 6}}}
		case "getMultipleAccounts":
			response := out.(*struct {
				Value []json.RawMessage `json:"value"`
			})
			response.Value = []json.RawMessage{json.RawMessage(`{"data":{"parsed":{"info":{"owner":"1nc1nerator11111111111111111111111111111111"}}}}`)}
		default:
			return errors.New("unexpected RPC method: " + method)
		}
		return nil
	}
	got := collectProtocolLPControlEvidence(context.Background(), rpc, "solana-mainnet", mint, creator, "PumpPool111")
	if got.PoolType != "pumpswap_amm" || got.PoolProgram != pumpSwapProgram || !got.CanonicalPool {
		t.Fatalf("pool identity=%#v", got)
	}
	if got.PoolCreator != creator || got.LPMint != lpMint || got.TokenVault != baseVault || got.QuoteVault != quoteVault {
		t.Fatalf("decoded fields=%#v", got)
	}
	if got.Status != services.LPControlVerifiedBurned || got.BurnedSharePct != 90 {
		t.Fatalf("control=%#v", got)
	}
	if got.VirtualQuoteReserve != 5 || got.EffectiveQuoteReserve != 105 {
		t.Fatalf("virtual reserve=%#v", got)
	}
}

func TestMeteoraDAMMV2CollectorReportsPermanentLockWithoutInventingLPMint(t *testing.T) {
	data := make([]byte, 568)
	tokenABytes, mint := protocolTestKey(12)
	copy(data[168:200], tokenABytes)
	tokenBBytes, quoteMint := protocolTestKey(42)
	copy(data[200:232], tokenBBytes)
	vaultABytes, vaultA := protocolTestKey(72)
	copy(data[232:264], vaultABytes)
	vaultBBytes, vaultB := protocolTestKey(102)
	copy(data[264:296], vaultBBytes)
	putUint128LE(data[360:376], 1000)
	putUint128LE(data[552:568], 250)
	balanceCalls := 0
	rpc := func(_ context.Context, _ string, method string, _ any, out any) error {
		switch method {
		case "getAccountInfo":
			response := out.(*rpcAccountInfoResponse)
			response.Context.Slot = 1001
			response.Value = &struct {
				Owner string `json:"owner"`
				Data  any    `json:"data"`
			}{Owner: meteoraDAMMV2Program, Data: []any{base64.StdEncoding.EncodeToString(data), "base64"}}
		case "getTokenAccountBalance":
			balanceCalls++
			response := out.(*rpcTokenBalanceResponse)
			response.Context.Slot = 1002
			response.Value.Decimals = 6
			if balanceCalls == 1 {
				response.Value.UIAmountString = "5000"
			} else {
				response.Value.UIAmountString = "250"
			}
		default:
			return errors.New("position pool must not request LP mint RPC: " + method)
		}
		return nil
	}
	got := collectProtocolLPControlEvidence(context.Background(), rpc, "solana-mainnet", mint, "", "MeteoraPool111")
	if got.PoolType != "meteora_damm_v2" || got.ControlModel != "position_nft" || got.PositionModel != "meteora_damm_v2_position_nft" {
		t.Fatalf("model=%#v", got)
	}
	if got.TokenVault != vaultA || got.QuoteVault != vaultB || got.QuoteMint != quoteMint || got.LPMint != "" {
		t.Fatalf("vaults=%#v", got)
	}
	if got.Status != services.LPControlVerifiedPermanentLocked || math.Abs(got.PermanentLockedSharePct-25) > 0.0001 {
		t.Fatalf("lock=%#v", got)
	}
	if got.PoolLiquidityRaw != "1000" || got.PermanentLockedLiquidityRaw != "250" {
		t.Fatalf("raw liquidity=%#v", got)
	}
}

func TestMeteoraDLMMCollectorDecodesPinnedBytemuckMintAndVaultOffsets(t *testing.T) {
	data := make([]byte, 216)
	tokenXBytes, mint := protocolTestKey(15)
	copy(data[88:120], tokenXBytes)
	tokenYBytes, quoteMint := protocolTestKey(45)
	copy(data[120:152], tokenYBytes)
	reserveXBytes, reserveX := protocolTestKey(75)
	copy(data[152:184], reserveXBytes)
	reserveYBytes, reserveY := protocolTestKey(105)
	copy(data[184:216], reserveYBytes)
	balanceCalls := 0
	rpc := func(_ context.Context, _ string, method string, _ any, out any) error {
		switch method {
		case "getAccountInfo":
			response := out.(*rpcAccountInfoResponse)
			response.Context.Slot = 1100
			response.Value = &struct {
				Owner string `json:"owner"`
				Data  any    `json:"data"`
			}{Owner: meteoraDLMMProgram, Data: []any{base64.StdEncoding.EncodeToString(data), "base64"}}
		case "getTokenAccountBalance":
			balanceCalls++
			response := out.(*rpcTokenBalanceResponse)
			response.Context.Slot = 1101
			if balanceCalls == 1 {
				response.Value.UIAmountString = "7000"
			} else {
				response.Value.UIAmountString = "350"
			}
		default:
			return errors.New("DLMM pool must not request LP mint RPC: " + method)
		}
		return nil
	}
	got := collectProtocolLPControlEvidence(context.Background(), rpc, "solana-mainnet", mint, "", "DLMM111")
	if !got.Available || got.PoolType != "meteora_dlmm" || got.ReasonCode != "dlmm_position_ownership_not_enumerated" {
		t.Fatalf("result=%#v", got)
	}
	if got.ControlModel != "position_nft" || got.LPMint != "" {
		t.Fatalf("model=%#v", got)
	}
	if got.TokenVault != reserveX || got.QuoteVault != reserveY || got.QuoteMint != quoteMint {
		t.Fatalf("vaults=%#v", got)
	}
	if got.TokenReserve != 7000 || got.QuoteReserve != 350 {
		t.Fatalf("reserves=%#v", got)
	}
}

func putUint128LE(target []byte, value uint64) {
	for i := range target {
		target[i] = 0
	}
	binary.LittleEndian.PutUint64(target[:8], value)
}
