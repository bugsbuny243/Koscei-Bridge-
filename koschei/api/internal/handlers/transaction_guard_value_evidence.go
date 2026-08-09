package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"sort"
	"strings"
)

const transactionGuardValueEvidenceVersion = "koschei-transaction-value-evidence-v1"

type transactionGuardValueSOLMovement struct {
	Origin       string `json:"origin"`
	Kind         string `json:"kind"`
	Source       string `json:"source,omitempty"`
	Destination  string `json:"destination,omitempty"`
	Lamports     string `json:"lamports"`
	WalletOrigin bool   `json:"wallet_origin"`
}

type transactionGuardValueTokenMovement struct {
	Origin       string `json:"origin"`
	Kind         string `json:"kind"`
	ProgramID    string `json:"program_id,omitempty"`
	Source       string `json:"source,omitempty"`
	Destination  string `json:"destination,omitempty"`
	Mint         string `json:"mint,omitempty"`
	AmountRaw    string `json:"amount_raw"`
	Decimals     *int   `json:"decimals,omitempty"`
	WalletOrigin bool   `json:"wallet_origin"`
}

type transactionGuardValueTokenAggregate struct {
	Mint                      string `json:"mint"`
	TransferRaw               string `json:"transfer_raw"`
	WalletOriginTransferRaw   string `json:"wallet_origin_transfer_raw"`
	BurnRaw                   string `json:"burn_raw"`
	WalletOriginBurnRaw       string `json:"wallet_origin_burn_raw"`
	MovementCount             int    `json:"movement_count"`
	WalletOriginMovementCount int    `json:"wallet_origin_movement_count"`
	Decimals                  *int   `json:"decimals,omitempty"`
	DecimalsConsistent        bool   `json:"decimals_consistent"`
}

type transactionGuardValueEvidence struct {
	Version                           string                                `json:"version"`
	Status                            string                                `json:"status"`
	Complete                          bool                                  `json:"complete"`
	TransactionFingerprint            string                                `json:"transaction_fingerprint"`
	Wallet                            string                                `json:"wallet,omitempty"`
	DecodeComplete                    bool                                  `json:"decode_complete"`
	CPIComplete                       bool                                  `json:"cpi_complete"`
	AutomaticBalanceComplete          bool                                  `json:"automatic_balance_complete"`
	UnresolvedCPIInstructionCount     int                                   `json:"unresolved_cpi_instruction_count"`
	InvalidMovementCount              int                                   `json:"invalid_movement_count"`
	ExplicitSOLLamports               string                                `json:"explicit_sol_lamports"`
	WalletExplicitSOLOutflowLamports  string                                `json:"wallet_explicit_sol_outflow_lamports"`
	WalletObservedSOLDeltaLamports    string                                `json:"wallet_observed_sol_delta_lamports,omitempty"`
	WalletObservedSOLSpentLamports    string                                `json:"wallet_observed_sol_spent_lamports,omitempty"`
	WalletObservedSOLReceivedLamports string                                `json:"wallet_observed_sol_received_lamports,omitempty"`
	WalletBalanceEvidenceStatus       string                                `json:"wallet_balance_evidence_status"`
	SOLMovements                      []transactionGuardValueSOLMovement    `json:"sol_movements"`
	TokenMovements                    []transactionGuardValueTokenMovement  `json:"token_movements"`
	TokenAggregates                   []transactionGuardValueTokenAggregate `json:"token_aggregates"`
	UnscopedTokenMovementCount        int                                   `json:"unscoped_token_movement_count"`
	FeeStatus                         string                                `json:"fee_status"`
	PriceStatus                       string                                `json:"price_status"`
	PolicyUseStatus                   string                                `json:"policy_use_status"`
	EvidenceHashSHA256                string                                `json:"evidence_hash_sha256"`
	Limitations                       []string                              `json:"limitations"`
}

type transactionGuardValueTokenAggregateAccumulator struct {
	transfer            *big.Int
	walletTransfer      *big.Int
	burn                *big.Int
	walletBurn          *big.Int
	movementCount       int
	walletMovementCount int
	decimals            *int
	decimalsConsistent  bool
}

func buildTransactionGuardValueEvidence(transaction, wallet string, decoded transactionGuardDecodedTransaction, cpi transactionGuardCPIFlowAnalysis) transactionGuardValueEvidence {
	wallet = strings.TrimSpace(wallet)
	automatic := decoded.AutomaticBalance
	cpiComplete := !cpi.Requested || cpi.Complete
	balanceComplete := !automatic.Requested || automatic.Complete
	out := transactionGuardValueEvidence{
		Version:                           transactionGuardValueEvidenceVersion,
		Status:                            "partial",
		TransactionFingerprint:            transactionFingerprint(transaction),
		Wallet:                            wallet,
		DecodeComplete:                    decoded.Available && decoded.Complete,
		CPIComplete:                       cpiComplete,
		AutomaticBalanceComplete:          balanceComplete,
		UnresolvedCPIInstructionCount:     cpi.UnresolvedInstructionCount,
		ExplicitSOLLamports:               "0",
		WalletExplicitSOLOutflowLamports:  "0",
		WalletObservedSOLDeltaLamports:    strings.TrimSpace(automatic.WalletSOLDeltaLamports),
		WalletObservedSOLSpentLamports:    strings.TrimSpace(automatic.WalletSOLSpentLamports),
		WalletObservedSOLReceivedLamports: strings.TrimSpace(automatic.WalletSOLReceivedLamports),
		WalletBalanceEvidenceStatus:       strings.TrimSpace(automatic.Status),
		SOLMovements:                      []transactionGuardValueSOLMovement{},
		TokenMovements:                    []transactionGuardValueTokenMovement{},
		TokenAggregates:                   []transactionGuardValueTokenAggregate{},
		FeeStatus:                         "unavailable_no_verified_fee_evidence",
		PriceStatus:                       "not_requested_v1",
		PolicyUseStatus:                   "evidence_only_not_enforced",
		Limitations:                       []string{},
	}
	if out.WalletBalanceEvidenceStatus == "" {
		out.WalletBalanceEvidenceStatus = "not_requested"
	}
	if out.WalletObservedSOLDeltaLamports == "" {
		out.WalletObservedSOLDeltaLamports = "0"
	}
	if out.WalletObservedSOLSpentLamports == "" {
		out.WalletObservedSOLSpentLamports = "0"
	}
	if out.WalletObservedSOLReceivedLamports == "" {
		out.WalletObservedSOLReceivedLamports = "0"
	}

	totalSOL := big.NewInt(0)
	walletSOL := big.NewInt(0)
	appendSOL := func(origin, kind, source, destination, raw string, walletOrigin bool) {
		amount, ok := transactionGuardValueNonNegativeInteger(raw)
		if !ok {
			out.InvalidMovementCount++
			return
		}
		out.SOLMovements = append(out.SOLMovements, transactionGuardValueSOLMovement{
			Origin:       origin,
			Kind:         kind,
			Source:       strings.TrimSpace(source),
			Destination:  strings.TrimSpace(destination),
			Lamports:     amount.String(),
			WalletOrigin: walletOrigin,
		})
		totalSOL.Add(totalSOL, amount)
		if walletOrigin {
			walletSOL.Add(walletSOL, amount)
		}
	}
	for _, movement := range decoded.SOLTransfers {
		appendSOL(
			"outer_instruction",
			movement.Kind,
			movement.Source,
			movement.Recipient,
			movement.Lamports,
			wallet != "" && strings.EqualFold(strings.TrimSpace(movement.Source), wallet),
		)
	}
	for _, movement := range cpi.AssetMovements {
		if !movement.InnerOnly || !strings.EqualFold(strings.TrimSpace(movement.AssetType), "SOL") {
			continue
		}
		appendSOL("inner_instruction", movement.Kind, movement.Source, movement.Destination, movement.AmountRaw, movement.WalletOrigin)
	}
	out.ExplicitSOLLamports = totalSOL.String()
	out.WalletExplicitSOLOutflowLamports = walletSOL.String()

	mintByTokenAccount := transactionGuardValueTokenAccountMints(automatic.Accounts)
	ownerByTokenAccount := transactionGuardValueTokenAccountOwners(automatic.Accounts)
	aggregates := map[string]*transactionGuardValueTokenAggregateAccumulator{}
	appendToken := func(origin, kind, programID, source, destination, mint, raw string, decimals *int, walletOrigin bool) {
		amount, ok := transactionGuardValueNonNegativeInteger(raw)
		if !ok {
			out.InvalidMovementCount++
			return
		}
		mint = strings.TrimSpace(mint)
		if mint == "" {
			mint = firstNonEmptyString(
				mintByTokenAccount[strings.TrimSpace(source)],
				mintByTokenAccount[strings.TrimSpace(destination)],
			)
		}
		out.TokenMovements = append(out.TokenMovements, transactionGuardValueTokenMovement{
			Origin:       origin,
			Kind:         kind,
			ProgramID:    strings.TrimSpace(programID),
			Source:       strings.TrimSpace(source),
			Destination:  strings.TrimSpace(destination),
			Mint:         mint,
			AmountRaw:    amount.String(),
			Decimals:     decimals,
			WalletOrigin: walletOrigin,
		})
		if mint == "" {
			out.UnscopedTokenMovementCount++
			return
		}
		aggregate := aggregates[mint]
		if aggregate == nil {
			aggregate = &transactionGuardValueTokenAggregateAccumulator{
				transfer:           big.NewInt(0),
				walletTransfer:     big.NewInt(0),
				burn:               big.NewInt(0),
				walletBurn:         big.NewInt(0),
				decimalsConsistent: true,
			}
			aggregates[mint] = aggregate
		}
		aggregate.movementCount++
		if walletOrigin {
			aggregate.walletMovementCount++
		}
		if decimals == nil {
			aggregate.decimalsConsistent = false
		} else if aggregate.decimals == nil {
			value := *decimals
			aggregate.decimals = &value
		} else if *aggregate.decimals != *decimals {
			aggregate.decimalsConsistent = false
		}
		switch kind {
		case "burn", "burn_checked":
			aggregate.burn.Add(aggregate.burn, amount)
			if walletOrigin {
				aggregate.walletBurn.Add(aggregate.walletBurn, amount)
			}
		default:
			aggregate.transfer.Add(aggregate.transfer, amount)
			if walletOrigin {
				aggregate.walletTransfer.Add(aggregate.walletTransfer, amount)
			}
		}
	}
	for _, operation := range decoded.TokenOperations {
		if operation.Kind != "transfer" && operation.Kind != "transfer_checked" && operation.Kind != "burn" && operation.Kind != "burn_checked" {
			continue
		}
		walletOrigin := wallet != "" &&
			(strings.EqualFold(strings.TrimSpace(operation.Authority), wallet) ||
				strings.EqualFold(strings.TrimSpace(operation.Source), wallet) ||
				strings.EqualFold(strings.TrimSpace(operation.Account), wallet))
		if !walletOrigin && wallet != "" {
			owner := firstNonEmptyString(
				ownerByTokenAccount[strings.TrimSpace(operation.Source)],
				ownerByTokenAccount[strings.TrimSpace(operation.Account)],
			)
			walletOrigin = strings.EqualFold(owner, wallet)
		}
		appendToken(
			"outer_instruction",
			operation.Kind,
			operation.ProgramID,
			firstNonEmptyString(operation.Source, operation.Account),
			operation.Destination,
			operation.Mint,
			operation.AmountRaw,
			operation.Decimals,
			walletOrigin,
		)
	}
	for _, movement := range cpi.AssetMovements {
		if !movement.InnerOnly || !strings.EqualFold(strings.TrimSpace(movement.AssetType), "token") {
			continue
		}
		appendToken(
			"inner_instruction",
			movement.Kind,
			movement.ProgramID,
			movement.Source,
			movement.Destination,
			movement.Mint,
			movement.AmountRaw,
			movement.Decimals,
			movement.WalletOrigin,
		)
	}

	mints := make([]string, 0, len(aggregates))
	for mint := range aggregates {
		mints = append(mints, mint)
	}
	sort.Strings(mints)
	for _, mint := range mints {
		aggregate := aggregates[mint]
		out.TokenAggregates = append(out.TokenAggregates, transactionGuardValueTokenAggregate{
			Mint:                      mint,
			TransferRaw:               aggregate.transfer.String(),
			WalletOriginTransferRaw:   aggregate.walletTransfer.String(),
			BurnRaw:                   aggregate.burn.String(),
			WalletOriginBurnRaw:       aggregate.walletBurn.String(),
			MovementCount:             aggregate.movementCount,
			WalletOriginMovementCount: aggregate.walletMovementCount,
			Decimals:                  aggregate.decimals,
			DecimalsConsistent:        aggregate.decimalsConsistent,
		})
	}

	out.Complete = out.DecodeComplete && out.CPIComplete && out.AutomaticBalanceComplete && out.InvalidMovementCount == 0 && out.UnscopedTokenMovementCount == 0
	if !out.DecodeComplete {
		out.Limitations = append(out.Limitations, "Automatic transaction decoding is incomplete; missing instructions are not treated as zero value.")
	}
	if !out.CPIComplete {
		out.Limitations = append(out.Limitations, "CPI asset-flow decoding is incomplete; unresolved inner instructions may contain additional value movement.")
	}
	if !out.AutomaticBalanceComplete {
		out.Limitations = append(out.Limitations, "Automatic balance evidence is incomplete; wallet net balance impact is not treated as a complete exposure measure.")
	}
	if out.InvalidMovementCount > 0 {
		out.Limitations = append(out.Limitations, "At least one decoded asset movement had an invalid raw integer amount and is excluded from aggregate totals.")
	}
	if out.UnscopedTokenMovementCount > 0 {
		out.Limitations = append(out.Limitations, "At least one token movement could not be scoped to a mint and is excluded from mint aggregates.")
	}
	out.Limitations = append(out.Limitations,
		"Transaction fee lamports are not independently verified in Value Evidence v1 and are not inferred from wallet net balance change.",
		"No token or SOL amount is converted to USD in Value Evidence v1; price evidence is intentionally separate.",
		"This evidence is observational only and is not used by Transaction Guard scoring or permit policy in v1.",
	)
	switch {
	case out.Complete:
		out.Status = "complete"
	case decoded.Available:
		out.Status = "partial"
	default:
		out.Status = "unavailable"
	}
	out.EvidenceHashSHA256 = transactionGuardValueEvidenceHash(out)
	return out
}

func transactionGuardValueNonNegativeInteger(raw string) (*big.Int, bool) {
	value := new(big.Int)
	if _, ok := value.SetString(strings.TrimSpace(raw), 10); !ok || value.Sign() < 0 {
		return nil, false
	}
	return value, true
}

func transactionGuardValueTokenAccountMints(accounts []transactionGuardAutomaticBalanceDelta) map[string]string {
	out := map[string]string{}
	for _, account := range accounts {
		if account.TokenAccount && strings.TrimSpace(account.Address) != "" && strings.TrimSpace(account.Mint) != "" {
			out[strings.TrimSpace(account.Address)] = strings.TrimSpace(account.Mint)
		}
	}
	return out
}

func transactionGuardValueTokenAccountOwners(accounts []transactionGuardAutomaticBalanceDelta) map[string]string {
	out := map[string]string{}
	for _, account := range accounts {
		if !account.TokenAccount || strings.TrimSpace(account.Address) == "" {
			continue
		}
		owner := firstNonEmptyString(strings.TrimSpace(account.PreTokenOwner), strings.TrimSpace(account.PostTokenOwner))
		if owner != "" {
			out[strings.TrimSpace(account.Address)] = owner
		}
	}
	return out
}

func transactionGuardValueEvidenceHash(value transactionGuardValueEvidence) string {
	value.EvidenceHashSHA256 = ""
	payload, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
