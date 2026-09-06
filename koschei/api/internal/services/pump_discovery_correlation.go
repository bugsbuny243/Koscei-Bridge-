package services

import (
	"context"
	"strings"
	"time"
)

type PumpDiscoveryCorrelation struct {
	Available             bool      `json:"available"`
	Status                string    `json:"status"`
	Mint                  string    `json:"mint"`
	Signature             string    `json:"signature,omitempty"`
	EventType             string    `json:"event_type,omitempty"`
	ObservationSource     string    `json:"observation_source"`
	VerificationSource    string    `json:"verification_source"`
	ObservedSlot          int64     `json:"observed_slot,omitempty"`
	CanonicalSlot         int64     `json:"canonical_slot,omitempty"`
	Program               string    `json:"program,omitempty"`
	MintReferenceObserved bool      `json:"mint_reference_observed"`
	SemanticStatus        string    `json:"semantic_status"`
	ReasonCode            string    `json:"reason_code,omitempty"`
	ObservedAt            time.Time `json:"observed_at"`
	Limitations           []string  `json:"limitations"`
}

// CorrelatePumpPortalDiscoveryEvent independently rereads a source-reported
// new-token/migration signature. It proves only that the exact transaction can
// be found and contains the requested mint plus a Pump/PumpSwap program. It
// deliberately does not claim that the transaction's migration/create semantic
// was decoded; event semantics remain source-reported until a dedicated decoder
// proves them. This projection cannot issue or change an ARVIS verdict.
func CorrelatePumpPortalDiscoveryEvent(ctx context.Context, rpcURL, verificationSource, mint, signature, eventType string, observedSlot int64) PumpDiscoveryCorrelation {
	out := PumpDiscoveryCorrelation{
		Status:             "not_requested",
		Mint:               strings.TrimSpace(mint),
		Signature:          strings.TrimSpace(signature),
		EventType:          strings.TrimSpace(eventType),
		ObservationSource:  "pumpportal",
		VerificationSource: strings.TrimSpace(verificationSource),
		ObservedSlot:       observedSlot,
		SemanticStatus:     "source_reported_not_independently_decoded",
		ObservedAt:         time.Now().UTC(),
		Limitations: []string{
			"A correlated signature confirms transaction presence, mint reference and Pump/PumpSwap program only; it does not independently prove create/migration semantics.",
		},
	}
	if out.Mint == "" {
		out.Status = "mint_required"
		return out
	}
	if out.Signature == "" {
		out.Status = "signature_unavailable"
		return out
	}
	if strings.TrimSpace(rpcURL) == "" {
		out.Status = "verification_source_unavailable"
		return out
	}
	if out.VerificationSource == "" {
		out.VerificationSource = "canonical_solana_rpc_fallback"
	}

	txs, err := SolanaGetTransactionsJSONParsedBatch(ctx, rpcURL, []string{out.Signature})
	if err != nil {
		out.Status = "verification_source_unavailable"
		out.Limitations = append(out.Limitations, "Canonical transaction reread failed: "+compactClusterError(err))
		return out
	}
	tx, ok := txs[out.Signature]
	if !ok || tx == nil {
		out.Status = "transaction_unavailable"
		return out
	}
	out.Available = true
	txMap := map[string]any(tx)
	out.CanonicalSlot = holderClusterInt64(txMap["slot"])
	out.Program = launchCounterpartyProgram(txMap)
	out.MintReferenceObserved = pumpDiscoveryTransactionReferencesMint(txMap, out.Mint)

	slotMatches := out.ObservedSlot <= 0 || out.CanonicalSlot <= 0 || out.ObservedSlot == out.CanonicalSlot
	programMatches := out.Program == "pump.fun" || out.Program == "pumpswap"
	switch {
	case !slotMatches:
		out.Status = "observed_mismatch"
		out.ReasonCode = "slot_mismatch"
	case !out.MintReferenceObserved:
		out.Status = "observed_mismatch"
		out.ReasonCode = "mint_reference_not_observed"
	case !programMatches:
		out.Status = "observed_mismatch"
		out.ReasonCode = "pump_program_not_observed"
	default:
		out.Status = "signature_correlated"
		out.ReasonCode = "canonical_transaction_reference_match"
	}
	return out
}

func pumpDiscoveryTransactionReferencesMint(tx map[string]any, mint string) bool {
	mint = strings.TrimSpace(mint)
	if mint == "" {
		return false
	}
	message := holderClusterMap(holderClusterMap(tx["transaction"])["message"])
	for _, key := range holderClusterAccountKeys(message["accountKeys"]) {
		if strings.TrimSpace(key) == mint {
			return true
		}
	}
	meta := holderClusterMap(tx["meta"])
	for _, field := range []string{"preTokenBalances", "postTokenBalances"} {
		for _, item := range holderClusterSlice(meta[field]) {
			balance := holderClusterMap(item)
			if strings.TrimSpace(holderClusterString(balance["mint"])) == mint {
				return true
			}
		}
	}
	return false
}
