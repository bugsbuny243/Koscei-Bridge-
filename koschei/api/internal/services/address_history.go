package services

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	defaultAddressHistoryPageSize = 250
	defaultAddressHistoryMaxPages = 8
)

type AddressHistoryOptions struct {
	PageSize int
	MaxPages int
}

type AddressHistoryEntry struct {
	Signature string    `json:"signature"`
	Slot      int64     `json:"slot"`
	Status    string    `json:"status"`
	BlockTime time.Time `json:"block_time,omitempty"`
}

type AddressHistoryReport struct {
	SchemaVersion      string                `json:"schema_version"`
	Status             string                `json:"status"`
	Network            string                `json:"network"`
	Address            string                `json:"address"`
	HistoryComplete    bool                  `json:"history_complete"`
	PagesFetched       int                   `json:"pages_fetched"`
	SignaturesSeen     int                   `json:"signatures_seen"`
	SuccessfulCount    int                   `json:"successful_count"`
	FailedCount        int                   `json:"failed_count"`
	FirstSeenAt        time.Time             `json:"first_seen_at,omitempty"`
	LastSeenAt         time.Time             `json:"last_seen_at,omitempty"`
	OldestSignature    string                `json:"oldest_signature,omitempty"`
	NewestSignature    string                `json:"newest_signature,omitempty"`
	NextCursor         string                `json:"next_cursor,omitempty"`
	Entries            []AddressHistoryEntry `json:"entries"`
	Limitations        []string              `json:"limitations"`
	EvidenceSource     string                `json:"evidence_source"`
	IdentityScope      string                `json:"identity_scope"`
	AttributionClaimed bool                  `json:"attribution_claimed"`
}

func CollectAddressHistory(ctx context.Context, rpcURL, network, address string, options AddressHistoryOptions) (AddressHistoryReport, error) {
	address = strings.TrimSpace(address)
	network = strings.TrimSpace(network)
	if network == "" {
		network = "solana-mainnet"
	}
	out := AddressHistoryReport{
		SchemaVersion:  "koschei-address-history-v1",
		Status:         "not_started",
		Network:        network,
		Address:        address,
		Entries:        []AddressHistoryEntry{},
		Limitations:    []string{},
		EvidenceSource: "solana_getSignaturesForAddress",
		IdentityScope:  "onchain_address_only",
	}
	if address == "" {
		out.Status = "address_required"
		return out, fmt.Errorf("address is required")
	}
	if strings.TrimSpace(rpcURL) == "" {
		out.Status = "rpc_unavailable"
		return out, fmt.Errorf("solana rpc url is empty")
	}
	pageSize := options.PageSize
	if pageSize <= 0 || pageSize > 1000 {
		pageSize = defaultAddressHistoryPageSize
	}
	maxPages := options.MaxPages
	if maxPages <= 0 {
		maxPages = defaultAddressHistoryMaxPages
	}
	if maxPages > 20 {
		maxPages = 20
	}

	before := ""
	seen := map[string]bool{}
	for page := 0; page < maxPages && ctx.Err() == nil; page++ {
		rows, err := SolanaGetSignaturesForAddressPage(ctx, rpcURL, address, SolanaSignaturePageOptions{Limit: pageSize, Before: before})
		if err != nil {
			out.Status = "collection_failed"
			out.Limitations = append(out.Limitations, "Address history pagination stopped because the RPC provider did not return the next page.")
			return out, err
		}
		out.PagesFetched++
		if len(rows) == 0 {
			out.HistoryComplete = true
			break
		}
		for _, row := range rows {
			signature := strings.TrimSpace(row.Signature)
			if signature == "" || seen[signature] {
				continue
			}
			seen[signature] = true
			entry := AddressHistoryEntry{Signature: signature, Slot: row.Slot, Status: "success"}
			if row.Err != nil {
				entry.Status = "failed"
				out.FailedCount++
			} else {
				out.SuccessfulCount++
			}
			if row.BlockTime != nil && *row.BlockTime > 0 {
				entry.BlockTime = time.Unix(*row.BlockTime, 0).UTC()
				if out.LastSeenAt.IsZero() || entry.BlockTime.After(out.LastSeenAt) {
					out.LastSeenAt = entry.BlockTime
				}
				if out.FirstSeenAt.IsZero() || entry.BlockTime.Before(out.FirstSeenAt) {
					out.FirstSeenAt = entry.BlockTime
				}
			}
			out.Entries = append(out.Entries, entry)
		}
		out.SignaturesSeen = len(out.Entries)
		if out.NewestSignature == "" && len(out.Entries) > 0 {
			out.NewestSignature = out.Entries[0].Signature
		}
		last := strings.TrimSpace(rows[len(rows)-1].Signature)
		if last == "" || last == before {
			out.HistoryComplete = true
			break
		}
		before = last
		out.OldestSignature = last
		if len(rows) < pageSize {
			out.HistoryComplete = true
			break
		}
	}

	if ctx.Err() != nil {
		out.Status = "bounded"
		out.NextCursor = before
		out.Limitations = append(out.Limitations, "Address history stopped at the request time budget; older history remains available through the returned cursor.")
		return out, ctx.Err()
	}
	if out.HistoryComplete {
		out.Status = "complete"
		out.NextCursor = ""
	} else {
		out.Status = "bounded"
		out.NextCursor = before
		out.Limitations = append(out.Limitations, fmt.Sprintf("Address history inspected at most %d pages of %d signatures; older history remains outside this run and is not treated as absent.", maxPages, pageSize))
	}
	if out.SignaturesSeen == 0 && out.HistoryComplete {
		out.Status = "complete_no_activity_observed"
	}
	return out, nil
}
