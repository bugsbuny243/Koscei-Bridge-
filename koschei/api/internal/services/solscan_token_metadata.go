package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// SolscanTokenMetadata is an external discovery record. Creator attribution
// remains OBSERVED until the create transaction is re-read from the configured
// Solana RPC provider and the creator is confirmed as a signer.
type SolscanTokenMetadata struct {
	Configured           bool            `json:"configured"`
	Available            bool            `json:"available"`
	Status               string          `json:"status"`
	Provider             string          `json:"provider"`
	Address              string          `json:"address"`
	Name                 string          `json:"name,omitempty"`
	Symbol               string          `json:"symbol,omitempty"`
	Creator              string          `json:"creator,omitempty"`
	CreateTransaction    string          `json:"create_transaction,omitempty"`
	CreatedTime          int64           `json:"created_time,omitempty"`
	CreatedAt            time.Time       `json:"created_at,omitempty"`
	FirstMintTransaction string          `json:"first_mint_transaction,omitempty"`
	FirstMintTime        int64           `json:"first_mint_time,omitempty"`
	FirstMintAt          time.Time       `json:"first_mint_at,omitempty"`
	MintAuthority        string          `json:"mint_authority,omitempty"`
	FreezeAuthority      string          `json:"freeze_authority,omitempty"`
	OnchainExtensions    json.RawMessage `json:"onchain_extensions,omitempty"`
	ObservedAt           time.Time       `json:"observed_at"`
	Limitations          []string        `json:"limitations"`
}

type solscanTokenMetaPayload struct {
	Address           string          `json:"address"`
	Name              string          `json:"name"`
	Symbol            string          `json:"symbol"`
	Creator           string          `json:"creator"`
	CreateTx          string          `json:"create_tx"`
	CreatedTime       int64           `json:"created_time"`
	FirstMintTx       string          `json:"first_mint_tx"`
	FirstMintTime     int64           `json:"first_mint_time"`
	MintAuthority     string          `json:"mint_authority"`
	FreezeAuthority   string          `json:"freeze_authority"`
	OnchainExtensions json.RawMessage `json:"onchain_extensions"`
}

func FetchSolscanTokenMetadata(ctx context.Context, mint string) SolscanTokenMetadata {
	return NewSolscanClientFromEnv().TokenMetadata(ctx, mint)
}

func (c *SolscanClient) TokenMetadata(ctx context.Context, mint string) SolscanTokenMetadata {
	mint = strings.TrimSpace(mint)
	out := SolscanTokenMetadata{
		Configured: strings.TrimSpace(c.APIKey) != "",
		Status:     "not_configured", Provider: "solscan_pro_api_v2", Address: mint,
		ObservedAt: time.Now().UTC(), Limitations: []string{},
	}
	if mint == "" {
		out.Status = "mint_required"
		out.Limitations = append(out.Limitations, "A token mint is required for Solscan token metadata discovery.")
		return out
	}
	if !out.Configured {
		out.Limitations = append(out.Limitations, "SOLSCAN_API_KEY is not configured; token creator discovery was skipped.")
		return out
	}

	var response solscanResponse[solscanTokenMetaPayload]
	if err := c.get(ctx, "/token/meta", url.Values{"address": []string{mint}}, &response); err != nil {
		out.Status = "collection_failed"
		out.Limitations = append(out.Limitations, "Solscan token metadata could not be collected: "+compactSolscanError(err))
		return out
	}
	if !response.Success {
		out.Status = "collection_failed"
		out.Limitations = append(out.Limitations, "Solscan token metadata response was unsuccessful: "+strings.TrimSpace(response.Errors.Message))
		return out
	}

	payload := response.Data
	if strings.TrimSpace(payload.Address) != "" {
		out.Address = strings.TrimSpace(payload.Address)
	}
	out.Available = true
	out.Name = strings.TrimSpace(payload.Name)
	out.Symbol = strings.TrimSpace(payload.Symbol)
	out.Creator = strings.TrimSpace(payload.Creator)
	out.CreateTransaction = strings.TrimSpace(payload.CreateTx)
	out.CreatedTime = payload.CreatedTime
	out.FirstMintTransaction = strings.TrimSpace(payload.FirstMintTx)
	out.FirstMintTime = payload.FirstMintTime
	out.MintAuthority = strings.TrimSpace(payload.MintAuthority)
	out.FreezeAuthority = strings.TrimSpace(payload.FreezeAuthority)
	out.OnchainExtensions = append(json.RawMessage(nil), payload.OnchainExtensions...)
	if payload.CreatedTime > 0 {
		out.CreatedAt = time.Unix(payload.CreatedTime, 0).UTC()
	}
	if payload.FirstMintTime > 0 {
		out.FirstMintAt = time.Unix(payload.FirstMintTime, 0).UTC()
	}
	if out.Creator == "" {
		out.Status = "metadata_without_creator"
		out.Limitations = append(out.Limitations, "Solscan token metadata was returned without a creator wallet.")
		return out
	}
	out.Status = "complete"
	return out
}

func validateSolscanTokenMetadata(meta SolscanTokenMetadata, expectedMint string) error {
	if !meta.Available {
		return fmt.Errorf("solscan token metadata unavailable: %s", strings.TrimSpace(meta.Status))
	}
	if strings.TrimSpace(meta.Address) != strings.TrimSpace(expectedMint) {
		return fmt.Errorf("solscan token metadata address mismatch")
	}
	return nil
}
