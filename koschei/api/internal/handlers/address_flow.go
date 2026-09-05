package handlers

import (
	"context"
	"sort"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const addressFlowSchemaVersion = "koschei-address-flow-v1"

type addressFlowTransfer struct {
	Direction          string    `json:"direction"`
	AssetType          string    `json:"asset_type"`
	Counterparty       string    `json:"counterparty"`
	Signature          string    `json:"signature"`
	Slot               int64     `json:"slot"`
	ObservedAt         time.Time `json:"observed_at"`
	AmountNative       float64   `json:"amount_native,omitempty"`
	TokenMint          string    `json:"token_mint,omitempty"`
	TokenAmount        float64   `json:"token_amount,omitempty"`
	VerificationStatus string    `json:"verification_status"`
	Source             string    `json:"source"`
}

type addressFlowCounterparty struct {
	Address            string   `json:"address"`
	InboundTransfers   int      `json:"inbound_transfers"`
	OutboundTransfers  int      `json:"outbound_transfers"`
	SOLIn              float64  `json:"sol_in,omitempty"`
	SOLOut             float64  `json:"sol_out,omitempty"`
	TokenTransfersIn   int      `json:"token_transfers_in"`
	TokenTransfersOut  int      `json:"token_transfers_out"`
	TokenMints         []string `json:"token_mints"`
	VerificationStatus string   `json:"verification_status"`
}

type addressFlowReport struct {
	SchemaVersion       string                    `json:"schema_version"`
	Status              string                    `json:"status"`
	Network             string                    `json:"network"`
	Address             string                    `json:"address"`
	HistoryComplete     bool                      `json:"history_complete"`
	FlowComplete        bool                      `json:"flow_complete"`
	SignaturesAvailable int                       `json:"signatures_available"`
	TransactionLimit    int                       `json:"transaction_limit"`
	TransactionsAsked   int                       `json:"transactions_requested"`
	TransactionsDecoded int                       `json:"transactions_decoded"`
	TransfersObserved   int                       `json:"transfers_observed"`
	CounterpartyCount   int                       `json:"counterparty_count"`
	InboundTransfers    int                       `json:"inbound_transfers"`
	OutboundTransfers   int                       `json:"outbound_transfers"`
	Counterparties      []addressFlowCounterparty `json:"counterparties"`
	Transfers           []addressFlowTransfer     `json:"transfers"`
	Limitations         []string                  `json:"limitations"`
	EvidenceSource      string                    `json:"evidence_source"`
	IdentityScope       string                    `json:"identity_scope"`
}

func newAddressFlowReport(wallet, network string) addressFlowReport {
	return addressFlowReport{
		SchemaVersion:  addressFlowSchemaVersion,
		Status:         "not_requested",
		Network:        strings.TrimSpace(network),
		Address:        strings.TrimSpace(wallet),
		Counterparties: []addressFlowCounterparty{},
		Transfers:      []addressFlowTransfer{},
		Limitations:    []string{},
		EvidenceSource: "solana_jsonparsed_transaction",
		IdentityScope:  "onchain_address_only",
	}
}

func (h *Handler) collectAddressFlow(ctx context.Context, wallet, network string, history services.AddressHistoryReport) addressFlowReport {
	wallet = strings.TrimSpace(wallet)
	out := newAddressFlowReport(wallet, network)
	out.HistoryComplete = history.HistoryComplete
	out.SignaturesAvailable = history.SuccessfulCount
	if wallet == "" {
		out.Status = "address_required"
		return out
	}
	if history.SignaturesSeen == 0 {
		if history.HistoryComplete {
			out.Status = "complete_no_activity_observed"
			out.FlowComplete = true
		} else {
			out.Status = "history_unavailable"
			out.Limitations = append(out.Limitations, "Fund-flow analysis requires observable address history.")
		}
		return out
	}

	txLimit := actorDefenseEnvInt("ARVIS_ADDRESS_FLOW_TRANSACTION_LIMIT", 80, 10, 250)
	transferLimit := actorDefenseEnvInt("ARVIS_ADDRESS_FLOW_TRANSFER_LIMIT", 300, 50, 1000)
	out.TransactionLimit = txLimit
	selected := selectAddressFlowEntries(history.Entries, txLimit)
	out.TransactionsAsked = len(selected)
	if len(selected) == 0 {
		out.Status = "no_successful_transactions"
		out.FlowComplete = history.HistoryComplete
		return out
	}

	rpcURL := creatorIntelRPCURL()
	if strings.TrimSpace(rpcURL) == "" {
		out.Status = "rpc_unavailable"
		out.Limitations = append(out.Limitations, "Solana RPC is unavailable for transaction-detail fund-flow analysis.")
		return out
	}

	signatures := make([]string, 0, len(selected))
	entryBySignature := make(map[string]services.AddressHistoryEntry, len(selected))
	for _, entry := range selected {
		signatures = append(signatures, entry.Signature)
		entryBySignature[entry.Signature] = entry
	}
	transactions, batchErr := services.SolanaGetTransactionsJSONParsedBatch(ctx, rpcURL, signatures)
	out.TransactionsDecoded = len(transactions)
	if batchErr != nil {
		out.Limitations = append(out.Limitations, "Some transaction details were unavailable from the RPC provider; missing details are not treated as absence of fund flow.")
	}

	dossier := services.ActorDefenseDossier{Wallet: wallet, Network: network}
	counterpartyState := map[string]*addressFlowCounterpartyBuilder{}
	truncated := false
	for _, signature := range signatures {
		if ctx.Err() != nil {
			out.Limitations = append(out.Limitations, "Fund-flow decoding stopped at the request time budget.")
			break
		}
		tx, ok := transactions[signature]
		if !ok || tx == nil {
			continue
		}
		txMap := map[string]any(tx)
		meta := creatorIntelMap(txMap["meta"])
		if meta["err"] != nil {
			continue
		}
		message := creatorIntelMap(creatorIntelMap(txMap["transaction"])["message"])
		keys, signers := creatorIntelAccountKeys(message)
		owners := actorDefenseTokenAccountOwners(meta, keys)
		actorSigned := actorDefenseContainsExact(signers, wallet)
		entry := entryBySignature[signature]
		signatureInfo := services.SolanaSignatureInfo{Signature: signature, Slot: entry.Slot}
		if !entry.BlockTime.IsZero() {
			unix := entry.BlockTime.Unix()
			signatureInfo.BlockTime = &unix
		}
		observedAt := actorDefenseObservedAt(signatureInfo, txMap)
		for index, instruction := range actorDefenseInstructions(message, meta) {
			items := actorDefenseInstructionEvidence(dossier, signatureInfo, observedAt, actorSigned, instruction, owners, map[string]bool{}, map[string]services.ActorDefenseRelatedActor{}, index)
			for _, item := range items {
				transfer, ok := addressFlowTransferFromEvidence(item)
				if !ok {
					continue
				}
				if len(out.Transfers) >= transferLimit {
					truncated = true
					break
				}
				out.Transfers = append(out.Transfers, transfer)
				applyAddressFlowCounterparty(counterpartyState, transfer)
				if transfer.Direction == "inbound" {
					out.InboundTransfers++
				} else {
					out.OutboundTransfers++
				}
			}
			if truncated {
				break
			}
		}
		if truncated {
			break
		}
	}
	out.TransfersObserved = len(out.Transfers)
	out.Counterparties = buildAddressFlowCounterparties(counterpartyState)
	out.CounterpartyCount = len(out.Counterparties)

	allSuccessfulSelected := history.SuccessfulCount == len(selected)
	allSelectedDecoded := len(transactions) == len(selected)
	out.FlowComplete = history.HistoryComplete && allSuccessfulSelected && allSelectedDecoded && !truncated && ctx.Err() == nil
	if out.FlowComplete {
		if out.TransfersObserved == 0 {
			out.Status = "complete_no_direct_flow_observed"
		} else {
			out.Status = "complete"
		}
		return out
	}
	out.Status = "bounded"
	if !history.HistoryComplete {
		out.Limitations = append(out.Limitations, "Address signature history itself is bounded, so fund-flow coverage cannot be complete.")
	}
	if !allSuccessfulSelected {
		out.Limitations = append(out.Limitations, "Transaction-detail analysis sampled the observed successful history because it exceeded the configured decode budget.")
	}
	if !allSelectedDecoded {
		out.Limitations = append(out.Limitations, "Not every selected transaction detail was available; flow completeness is withheld.")
	}
	if truncated {
		out.Limitations = append(out.Limitations, "Transfer output reached its bounded evidence limit; additional decoded transfers were not emitted.")
	}
	return out
}

func selectAddressFlowEntries(entries []services.AddressHistoryEntry, limit int) []services.AddressHistoryEntry {
	successful := make([]services.AddressHistoryEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Status == "success" && strings.TrimSpace(entry.Signature) != "" {
			successful = append(successful, entry)
		}
	}
	if limit <= 0 || len(successful) <= limit {
		return successful
	}
	if limit == 1 {
		return successful[:1]
	}
	out := make([]services.AddressHistoryEntry, 0, limit)
	used := map[int]bool{}
	for i := 0; i < limit; i++ {
		index := i * (len(successful) - 1) / (limit - 1)
		if used[index] {
			continue
		}
		used[index] = true
		out = append(out, successful[index])
	}
	return out
}

func addressFlowTransferFromEvidence(item services.ActorDefenseEvidenceRecord) (addressFlowTransfer, bool) {
	transfer := addressFlowTransfer{
		Counterparty:       strings.TrimSpace(item.CounterpartID),
		Signature:          strings.TrimSpace(item.Signature),
		Slot:               item.Slot,
		ObservedAt:         item.ObservedAt,
		AmountNative:       item.AmountNative,
		TokenMint:          strings.TrimSpace(item.TokenMint),
		TokenAmount:        item.TokenAmount,
		VerificationStatus: strings.TrimSpace(item.VerificationStatus),
		Source:             strings.TrimSpace(item.Source),
	}
	switch item.Relation {
	case "direct_sol_transfer_in":
		transfer.Direction = "inbound"
		transfer.AssetType = "SOL"
	case "direct_sol_transfer_out":
		transfer.Direction = "outbound"
		transfer.AssetType = "SOL"
	case "direct_token_transfer_in":
		transfer.Direction = "inbound"
		transfer.AssetType = "SPL_TOKEN"
	case "direct_token_transfer_out":
		transfer.Direction = "outbound"
		transfer.AssetType = "SPL_TOKEN"
	default:
		return addressFlowTransfer{}, false
	}
	if transfer.Counterparty == "" {
		return addressFlowTransfer{}, false
	}
	return transfer, true
}

type addressFlowCounterpartyBuilder struct {
	item  addressFlowCounterparty
	mints map[string]bool
}

func applyAddressFlowCounterparty(state map[string]*addressFlowCounterpartyBuilder, transfer addressFlowTransfer) {
	builder := state[transfer.Counterparty]
	if builder == nil {
		builder = &addressFlowCounterpartyBuilder{
			item: addressFlowCounterparty{Address: transfer.Counterparty, VerificationStatus: "verified", TokenMints: []string{}},
			mints: map[string]bool{},
		}
		state[transfer.Counterparty] = builder
	}
	if transfer.VerificationStatus != "verified" {
		builder.item.VerificationStatus = transfer.VerificationStatus
	}
	if transfer.Direction == "inbound" {
		builder.item.InboundTransfers++
		if transfer.AssetType == "SOL" {
			builder.item.SOLIn += transfer.AmountNative
		} else {
			builder.item.TokenTransfersIn++
		}
	} else {
		builder.item.OutboundTransfers++
		if transfer.AssetType == "SOL" {
			builder.item.SOLOut += transfer.AmountNative
		} else {
			builder.item.TokenTransfersOut++
		}
	}
	if transfer.TokenMint != "" {
		builder.mints[transfer.TokenMint] = true
	}
}

func buildAddressFlowCounterparties(state map[string]*addressFlowCounterpartyBuilder) []addressFlowCounterparty {
	addresses := make([]string, 0, len(state))
	for address := range state {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	out := make([]addressFlowCounterparty, 0, len(addresses))
	for _, address := range addresses {
		builder := state[address]
		mints := make([]string, 0, len(builder.mints))
		for mint := range builder.mints {
			mints = append(mints, mint)
		}
		sort.Strings(mints)
		builder.item.TokenMints = mints
		out = append(out, builder.item)
	}
	return out
}
