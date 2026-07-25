package services

import "time"

const (
	LPControlVerifiedBurned          = "burned"
	LPControlVerifiedLocked          = "locked_until"
	LPControlVerifiedPermanentLocked = "permanently_locked"
	LPControlHeldByCreator           = "held_by_creator"
	LPControlUnverified              = "unverified"
	LPControlNotApplicable           = "not_applicable"
	LPControlSourceUnavailable       = "source_unavailable"
)

// LPControlEvidence is informational evidence only. It cannot issue a grade and
// never infers intent from LP ownership alone.
type LPControlEvidence struct {
	Available                   bool                         `json:"available"`
	Status                      string                       `json:"status"`
	ReasonCode                  string                       `json:"reason_code,omitempty"`
	PoolAddress                 string                       `json:"pool_address,omitempty"`
	PoolProgram                 string                       `json:"pool_program,omitempty"`
	PoolType                    string                       `json:"pool_type,omitempty"`
	ControlModel                string                       `json:"control_model,omitempty"`
	PositionModel               string                       `json:"position_model,omitempty"`
	PoolCreator                 string                       `json:"pool_creator,omitempty"`
	CreatorWallet               string                       `json:"creator_wallet,omitempty"`
	CanonicalPool               bool                         `json:"canonical_pool"`
	TokenMint                   string                       `json:"token_mint,omitempty"`
	QuoteMint                   string                       `json:"quote_mint,omitempty"`
	LPMint                      string                       `json:"lp_mint,omitempty"`
	TokenVault                  string                       `json:"token_vault,omitempty"`
	QuoteVault                  string                       `json:"quote_vault,omitempty"`
	ReadSlot                    uint64                       `json:"read_slot,omitempty"`
	TokenReserve                float64                      `json:"token_reserve,omitempty"`
	QuoteReserve                float64                      `json:"quote_reserve,omitempty"`
	VirtualQuoteReserve         float64                      `json:"virtual_quote_reserve,omitempty"`
	EffectiveQuoteReserve       float64                      `json:"effective_quote_reserve,omitempty"`
	ReserveLiquidityUSD         float64                      `json:"reserve_liquidity_usd,omitempty"`
	ReserveValueSource          string                       `json:"reserve_value_source,omitempty"`
	LPSupply                    float64                      `json:"lp_supply,omitempty"`
	LPSupplySource              string                       `json:"lp_supply_source,omitempty"`
	BurnedSharePct              float64                      `json:"burned_share_pct,omitempty"`
	LargestLPHolders            []LPHolderEvidence           `json:"largest_lp_holders"`
	DominantLPOwner             string                       `json:"dominant_lp_owner,omitempty"`
	DominantLPTokenAccount      string                       `json:"dominant_lp_token_account,omitempty"`
	DominantLPSharePct          float64                      `json:"dominant_lp_share_pct,omitempty"`
	DominantLPClassification    string                       `json:"dominant_lp_classification,omitempty"`
	CreatorRelation             string                       `json:"creator_relation,omitempty"`
	LockerProgram               string                       `json:"locker_program,omitempty"`
	LockerAccount               string                       `json:"locker_account,omitempty"`
	LockedUntil                 *time.Time                   `json:"locked_until,omitempty"`
	LockedLPAmount              float64                      `json:"locked_lp_amount,omitempty"`
	LockedLPSharePct            float64                      `json:"locked_lp_share_pct,omitempty"`
	LockedLPTokenAccounts       []string                     `json:"locked_lp_token_accounts"`
	LockedLPAuthorityAccounts   []string                     `json:"locked_lp_authority_accounts"`
	LockedPositionCount         int                          `json:"locked_position_count"`
	LockedPositionLiquidityRaw  string                       `json:"locked_position_liquidity_raw,omitempty"`
	PositionEnumerationStatus   string                       `json:"position_enumeration_status,omitempty"`
	PositionEnumerationLimit    int                          `json:"position_enumeration_limit,omitempty"`
	LockedPositions             []CLMMLockedPositionEvidence `json:"locked_positions"`
	CreatorLPSharePct           float64                      `json:"creator_lp_share_pct,omitempty"`
	PoolLiquidityRaw            string                       `json:"pool_liquidity_raw,omitempty"`
	PermanentLockedLiquidityRaw string                       `json:"permanent_locked_liquidity_raw,omitempty"`
	PermanentLockedSharePct     float64                      `json:"permanent_locked_share_pct,omitempty"`
	MovementStatus              string                       `json:"movement_status,omitempty"`
	MovementWindowSignatures    int                          `json:"movement_window_signatures"`
	MovementWindowParsed        int                          `json:"movement_window_parsed"`
	MovementWindowFailures      int                          `json:"movement_window_failures"`
	LiquidityMovements          []LiquidityMovementEvidence  `json:"liquidity_movements"`
	ObservedAt                  time.Time                    `json:"observed_at"`
	EvidenceKeys                []string                     `json:"evidence_keys"`
	Limitations                 []string                     `json:"limitations"`
}

type LPHolderEvidence struct {
	TokenAccount   string  `json:"token_account"`
	OwnerWallet    string  `json:"owner_wallet,omitempty"`
	Amount         float64 `json:"amount"`
	SharePct       float64 `json:"share_pct"`
	AccountOwner   string  `json:"account_owner,omitempty"`
	Classification string  `json:"classification,omitempty"`
}

// CLMMLockedPositionEvidence represents one independently verified Raydium
// Burn & Earn lock-state, personal-position and custody-token-account chain.
// LiquidityRaw is a CLMM position liquidity integer; it is not a percentage or
// a token amount and must not be divided by the pool's active-tick liquidity.
type CLMMLockedPositionEvidence struct {
	LockedPositionAccount string   `json:"locked_position_account"`
	PositionOwner          string   `json:"position_owner"`
	PositionAccount        string   `json:"position_account"`
	PositionNFTMint        string   `json:"position_nft_mint"`
	LockedNFTAccount       string   `json:"locked_nft_account"`
	CustodyAuthority       string   `json:"custody_authority"`
	FeeNFTMint             string   `json:"fee_nft_mint"`
	TickLowerIndex         int32    `json:"tick_lower_index"`
	TickUpperIndex         int32    `json:"tick_upper_index"`
	LiquidityRaw           string   `json:"liquidity_raw"`
	RecentEpoch            uint64   `json:"recent_epoch"`
	ReadSlot               uint64   `json:"read_slot,omitempty"`
	VerificationStatus     string   `json:"verification_status"`
	EvidenceKeys           []string `json:"evidence_keys"`
}

type LiquidityMovementEvidence struct {
	Kind               string   `json:"kind"`
	Signature          string   `json:"signature"`
	Slot               int64    `json:"slot,omitempty"`
	BlockTime          string   `json:"block_time,omitempty"`
	ActorWallet        string   `json:"actor_wallet,omitempty"`
	SourceWallet       string   `json:"source_wallet,omitempty"`
	DestinationWallet  string   `json:"destination_wallet,omitempty"`
	CreatorRelated     bool     `json:"creator_related"`
	CreatorRelation    string   `json:"creator_relation,omitempty"`
	PoolAddress        string   `json:"pool_address"`
	Program            string   `json:"program"`
	TokenDelta         float64  `json:"token_delta,omitempty"`
	QuoteDelta         float64  `json:"quote_delta,omitempty"`
	InstructionTypes   []string `json:"instruction_types"`
	EvidenceKey        string   `json:"evidence_key"`
	Source             string   `json:"source"`
	VerificationStatus string   `json:"verification_status"`
}

// JupiterMarketContext is optional context. Provider failure never changes core
// evidence, a verdict, a pathway status or signing.
type JupiterMarketContext struct {
	Available               bool      `json:"available"`
	Status                  string    `json:"status"`
	PriceAvailable          bool      `json:"price_available"`
	PriceUSD                float64   `json:"price_usd,omitempty"`
	PriceBlockID            uint64    `json:"price_block_id,omitempty"`
	PriceObservedAt         time.Time `json:"price_observed_at,omitempty"`
	DexScreenerPriceUSD     float64   `json:"dexscreener_price_usd,omitempty"`
	PriceDifferencePct      float64   `json:"price_difference_pct,omitempty"`
	SellImpactAvailable     bool      `json:"sell_impact_available"`
	SellInputAmountRaw      string    `json:"sell_input_amount_raw,omitempty"`
	SellOutputAmountRaw     string    `json:"sell_output_amount_raw,omitempty"`
	SellOutputMint          string    `json:"sell_output_mint,omitempty"`
	EstimatedPriceImpactPct float64   `json:"estimated_price_impact_pct,omitempty"`
	QuoteContextSlot        uint64    `json:"quote_context_slot,omitempty"`
	QuoteObservedAt         time.Time `json:"quote_observed_at,omitempty"`
	RouteLabels             []string  `json:"route_labels"`
	Limitations             []string  `json:"limitations"`
}
