package services

import (
	"context"
	"strings"
)

const (
	defaultTokenMetadataCreationSignatureLimit   = 100
	defaultTokenMetadataCreationTransactionLimit = 16
)

type boundedMintCreationResult struct {
	Observation           heliusMintCreationObservation
	SignaturesSeen        int
	TransactionsRequested int
	TransactionsParsed    int
	HistoryBounded        bool
}

// fetchBoundedMintCreationObservation preserves the creation-signature evidence
// needed for canonical creator verification without silently spending a Helius
// getTransactionsForAddress archival call. It inspects the oldest successful
// transactions inside a bounded recent mint-signature window and reports the
// window boundary separately; missing creation evidence is never treated as a
// complete-history or clean result when that boundary was reached.
func fetchBoundedMintCreationObservation(ctx context.Context, rpcURL, mint string) (boundedMintCreationResult, error) {
	out := boundedMintCreationResult{}
	rpcURL = strings.TrimSpace(rpcURL)
	mint = strings.TrimSpace(mint)
	if rpcURL == "" {
		return out, errSolanaRPCURLRequired()
	}
	if mint == "" {
		return out, errSolanaAddressRequired()
	}

	signatureLimit := holderScanEnvInt(
		"TOKEN_METADATA_CREATION_SIGNATURE_LIMIT",
		defaultTokenMetadataCreationSignatureLimit,
		10,
		500,
	)
	transactionLimit := holderScanEnvInt(
		"TOKEN_METADATA_CREATION_TRANSACTION_LIMIT",
		defaultTokenMetadataCreationTransactionLimit,
		1,
		50,
	)

	signatures, err := SolanaGetSignaturesForAddressPage(ctx, rpcURL, mint, SolanaSignaturePageOptions{Limit: signatureLimit})
	if err != nil {
		return out, err
	}
	out.SignaturesSeen = len(signatures)
	out.HistoryBounded = len(signatures) >= signatureLimit && len(signatures) > 0

	selected := make([]string, 0, transactionLimit)
	infoBySignature := map[string]SolanaSignatureInfo{}
	seen := map[string]bool{}
	for index := len(signatures) - 1; index >= 0 && len(selected) < transactionLimit; index-- {
		row := signatures[index]
		signature := strings.TrimSpace(row.Signature)
		if signature == "" || row.Err != nil || seen[signature] {
			continue
		}
		seen[signature] = true
		selected = append(selected, signature)
		infoBySignature[signature] = row
	}
	out.TransactionsRequested = len(selected)
	if len(selected) == 0 {
		return out, nil
	}

	transactions, detailErr := fetchCreatedMintRPCTransactions(ctx, rpcURL, selected)
	out.TransactionsParsed = len(transactions)
	for _, signature := range selected {
		tx, ok := transactions[signature]
		if !ok || tx == nil {
			continue
		}
		observation, matched := extractMintCreationObservation(map[string]any(tx), mint)
		if !matched {
			continue
		}
		info := infoBySignature[signature]
		if strings.TrimSpace(observation.Signature) == "" {
			observation.Signature = signature
		}
		if observation.Slot <= 0 {
			observation.Slot = info.Slot
		}
		if observation.BlockTime <= 0 && info.BlockTime != nil {
			observation.BlockTime = *info.BlockTime
		}
		out.Observation = observation
		return out, detailErr
	}
	return out, detailErr
}

// Keep the helper independent from fmt-created message strings so callers can
// preserve the existing RPC error vocabulary and tests can assert error type by
// message only at the transport boundary.
func errSolanaRPCURLRequired() error {
	return &tokenMetadataCreationInputError{message: "solana rpc url is empty"}
}

func errSolanaAddressRequired() error {
	return &tokenMetadataCreationInputError{message: "solana address is empty"}
}

type tokenMetadataCreationInputError struct {
	message string
}

func (e *tokenMetadataCreationInputError) Error() string {
	if e == nil {
		return "token metadata creation input error"
	}
	return e.message
}
