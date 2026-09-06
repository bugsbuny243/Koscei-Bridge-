package services

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"time"
)

const defaultPumpTradeCorrelationLimit = 12

type PumpTradeCorrelationEvidence struct {
	Signature          string `json:"signature"`
	Trader             string `json:"trader"`
	Side               string `json:"side"`
	ObservedSlot       int64  `json:"observed_slot,omitempty"`
	CanonicalSlot      int64  `json:"canonical_slot,omitempty"`
	Program            string `json:"program,omitempty"`
	VerificationStatus string `json:"verification_status"`
	ReasonCode         string `json:"reason_code,omitempty"`
}

type PumpTradeCorrelationReport struct {
	Available          bool                           `json:"available"`
	Status             string                         `json:"status"`
	Mint               string                         `json:"mint"`
	ObservationSource  string                         `json:"observation_source"`
	VerificationSource string                         `json:"verification_source"`
	ObservedCount      int                            `json:"observed_count"`
	SelectedCount      int                            `json:"selected_count"`
	VerifiedCount      int                            `json:"verified_count"`
	MismatchCount      int                            `json:"mismatch_count"`
	UnavailableCount   int                            `json:"unavailable_count"`
	VerificationLimit  int                            `json:"verification_limit"`
	Evidence           []PumpTradeCorrelationEvidence `json:"evidence"`
	ObservedAt         time.Time                      `json:"observed_at"`
	Limitations        []string                       `json:"limitations"`
}

// CorrelatePumpPortalTradeEvents re-reads a bounded subset of live PumpPortal
// observations from canonical Solana transaction history. PumpPortal remains an
// OBSERVED source until the on-chain transaction independently confirms the
// exact mint, trader, direction and a Pump/PumpSwap program. The projection is
// evidence-only and cannot issue or change an ARVIS verdict.
func CorrelatePumpPortalTradeEvents(ctx context.Context, db *sql.DB, rpcURL, verificationSource, mint string, limit int) PumpTradeCorrelationReport {
	mint = strings.TrimSpace(mint)
	verificationSource = strings.TrimSpace(verificationSource)
	if verificationSource == "" {
		verificationSource = "canonical_solana_rpc"
	}
	if limit <= 0 || limit > 50 {
		limit = defaultPumpTradeCorrelationLimit
	}
	out := PumpTradeCorrelationReport{
		Status:             "not_observed",
		Mint:               mint,
		ObservationSource:  "pumpportal",
		VerificationSource: verificationSource,
		VerificationLimit:  limit,
		Evidence:           []PumpTradeCorrelationEvidence{},
		ObservedAt:         time.Now().UTC(),
		Limitations:        []string{"PumpPortal observations are not upgraded to verified evidence unless the canonical transaction independently matches the mint, trader, direction and Pump/PumpSwap program."},
	}
	if mint == "" {
		out.Status = "mint_required"
		return out
	}
	trades, err := loadTokenTradeEvents(ctx, db, mint, 2000)
	if err != nil {
		out.Status = "ledger_unavailable"
		out.Limitations = append(out.Limitations, "PumpPortal trade ledger could not be read: "+compactClusterError(err))
		return out
	}
	observed := make([]LaunchTrade, 0, len(trades))
	seen := map[string]bool{}
	for _, trade := range trades {
		signature := strings.TrimSpace(trade.Signature)
		if !strings.EqualFold(strings.TrimSpace(trade.Source), "pumpportal") || signature == "" || seen[signature] {
			continue
		}
		seen[signature] = true
		observed = append(observed, trade)
	}
	out.ObservedCount = len(observed)
	if len(observed) == 0 {
		return out
	}
	if strings.TrimSpace(rpcURL) == "" {
		out.Status = "verification_source_unavailable"
		out.UnavailableCount = minInt(len(observed), limit)
		out.Limitations = append(out.Limitations, "Canonical Solana transaction source is unavailable; PumpPortal events remain observed-only.")
		return out
	}
	if len(observed) > limit {
		observed = observed[:limit]
		out.Limitations = append(out.Limitations, fmt.Sprintf("Correlation is bounded to the earliest %d PumpPortal signatures for this investigation.", limit))
	}
	out.SelectedCount = len(observed)
	keys := make([]string, 0, len(observed))
	for _, trade := range observed {
		keys = append(keys, strings.TrimSpace(trade.Signature))
	}
	transactions, batchErr := SolanaGetTransactionsJSONParsedBatch(ctx, rpcURL, keys)
	if batchErr != nil {
		out.Limitations = append(out.Limitations, "Canonical transaction batch was partially unavailable: "+compactClusterError(batchErr))
	}
	for _, trade := range observed {
		tx, ok := transactions[strings.TrimSpace(trade.Signature)]
		if !ok || tx == nil {
			out.UnavailableCount++
			out.Evidence = append(out.Evidence, pumpTradeCorrelationUnavailable(trade))
			continue
		}
		evidence := correlatePumpPortalTradeTransaction(trade, tx, mint)
		switch evidence.VerificationStatus {
		case "verified_correlated":
			out.VerifiedCount++
		default:
			out.MismatchCount++
		}
		out.Evidence = append(out.Evidence, evidence)
	}
	out.Available = len(transactions) > 0
	switch {
	case out.VerifiedCount == out.SelectedCount && out.SelectedCount > 0:
		out.Status = "verified"
	case out.VerifiedCount > 0:
		out.Status = "partial"
	case out.MismatchCount > 0:
		out.Status = "unverified"
	default:
		out.Status = "verification_source_unavailable"
	}
	return out
}

func correlatePumpPortalTradeTransaction(trade LaunchTrade, tx SolanaTransactionResult, mint string) PumpTradeCorrelationEvidence {
	evidence := PumpTradeCorrelationEvidence{
		Signature: strings.TrimSpace(trade.Signature),
		Trader:    strings.TrimSpace(trade.Trader),
		Side:      strings.ToLower(strings.TrimSpace(trade.Side)),
		ObservedSlot: trade.Slot,
		VerificationStatus: "observed_mismatch",
	}
	txMap := map[string]any(tx)
	evidence.CanonicalSlot = holderClusterInt64(txMap["slot"])
	evidence.Program = launchCounterpartyProgram(txMap)
	delta := holderClusterOwnerTokenDelta(txMap, strings.TrimSpace(mint), evidence.Trader)
	canonicalSide := ""
	if math.Abs(delta) > holderClusterFlowEpsilon {
		canonicalSide = "buy"
		if delta < 0 {
			canonicalSide = "sell"
		}
	}
	slotMatches := evidence.ObservedSlot <= 0 || evidence.CanonicalSlot <= 0 || evidence.ObservedSlot == evidence.CanonicalSlot
	programMatches := evidence.Program == "pump.fun" || evidence.Program == "pumpswap"
	sideMatches := canonicalSide != "" && canonicalSide == evidence.Side
	if slotMatches && programMatches && sideMatches {
		evidence.VerificationStatus = "verified_correlated"
		evidence.ReasonCode = "canonical_transaction_match"
		return evidence
	}
	switch {
	case !slotMatches:
		evidence.ReasonCode = "slot_mismatch"
	case !programMatches:
		evidence.ReasonCode = "pump_program_not_observed"
	case canonicalSide == "":
		evidence.ReasonCode = "trader_token_delta_not_observed"
	default:
		evidence.ReasonCode = "trade_direction_mismatch"
	}
	return evidence
}

func pumpTradeCorrelationUnavailable(trade LaunchTrade) PumpTradeCorrelationEvidence {
	return PumpTradeCorrelationEvidence{
		Signature: strings.TrimSpace(trade.Signature),
		Trader: strings.TrimSpace(trade.Trader),
		Side: strings.ToLower(strings.TrimSpace(trade.Side)),
		ObservedSlot: trade.Slot,
		VerificationStatus: "observed_unverified",
		ReasonCode: "canonical_transaction_unavailable",
	}
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
