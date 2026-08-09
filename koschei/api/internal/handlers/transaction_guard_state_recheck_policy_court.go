package handlers

import (
	"context"
	"os"
	"strings"

	"koschei/api/internal/web3"
)

func collectTransactionGuardStateRecheckEvidenceCourtWithRequirement(ctx context.Context, network string, addresses []string, requirement transactionGuardStateRecheckCourtRequirement) web3.EvidenceCourtResult {
	if !requirement.Required {
		return collectTransactionGuardStateRecheckEvidenceCourt(ctx, network, addresses)
	}
	client := web3.NewSolanaRPC(nil)
	params := []any{
		append([]string(nil), addresses...),
		map[string]any{"encoding": "base64", "commitment": "processed"},
	}
	primaryURL := web3.SolanaRPCURL(network, strings.TrimSpace(os.Getenv("ALCHEMY_API_KEY")))
	return client.EvidenceCourtWithCanonicalizerExcludingRequired(
		ctx,
		network,
		"getMultipleAccounts",
		params,
		primaryURL,
		requirement.RequiredWitnesses,
		transactionGuardStateRecheckCourtCanonicalizer(addresses),
	)
}
