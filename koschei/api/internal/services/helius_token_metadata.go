package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HeliusTokenMetadata is discovery-only. Creator attribution remains OBSERVED
// until the creation transaction is re-read from canonical Solana RPC and the
// candidate wallet is confirmed as a signer of the exact create instruction.
type HeliusTokenMetadata struct {
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

type heliusTokenMetadataResponse struct {
	Result struct {
		ID      string `json:"id"`
		Content struct {
			Metadata struct {
				Name          string `json:"name"`
				Symbol        string `json:"symbol"`
				TokenStandard string `json:"token_standard"`
			} `json:"metadata"`
		} `json:"content"`
		Authorities []struct {
			Address string   `json:"address"`
			Scopes  []string `json:"scopes"`
		} `json:"authorities"`
		Creators []struct {
			Address  string `json:"address"`
			Verified bool   `json:"verified"`
			Share    int    `json:"share"`
		} `json:"creators"`
		TokenInfo struct {
			Symbol          string `json:"symbol"`
			MintAuthority   string `json:"mint_authority"`
			FreezeAuthority string `json:"freeze_authority"`
		} `json:"token_info"`
		MintExtensions json.RawMessage `json:"mint_extensions"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type heliusMintCreationObservation struct {
	Creator   string
	Signature string
	Slot      int64
	BlockTime int64
}

func FetchHeliusTokenMetadata(ctx context.Context, rpcURL, mint string) HeliusTokenMetadata {
	mint = strings.TrimSpace(mint)
	out := HeliusTokenMetadata{
		Status: "not_configured", Provider: "helius_das_and_rpc", Address: mint,
		ObservedAt: time.Now().UTC(), Limitations: []string{},
	}
	if mint == "" {
		out.Status = "mint_required"
		out.Limitations = append(out.Limitations, "A token mint is required for Helius metadata discovery.")
		return out
	}
	apiKey := heliusEnhancedAPIKey(rpcURL)
	if apiKey == "" {
		out.Limitations = append(out.Limitations, "No Helius API key resolved; token metadata discovery was skipped.")
		return out
	}
	out.Configured = true
	endpoint := heliusRPCProviderURL(rpcURL, apiKey)

	asset, assetErr := fetchHeliusTokenAsset(ctx, endpoint, mint)
	if assetErr == nil {
		out.Available = true
		if strings.TrimSpace(asset.Result.ID) != "" {
			out.Address = strings.TrimSpace(asset.Result.ID)
		}
		out.Name = strings.TrimSpace(asset.Result.Content.Metadata.Name)
		out.Symbol = firstNonEmptyHeliusMetadataString(asset.Result.Content.Metadata.Symbol, asset.Result.TokenInfo.Symbol)
		out.MintAuthority = strings.TrimSpace(asset.Result.TokenInfo.MintAuthority)
		out.FreezeAuthority = strings.TrimSpace(asset.Result.TokenInfo.FreezeAuthority)
		out.OnchainExtensions = append(json.RawMessage(nil), asset.Result.MintExtensions...)
		out.Creator = verifiedHeliusAssetCreator(asset)
	} else {
		out.Limitations = append(out.Limitations, "Helius DAS getAsset failed: "+compactClusterError(assetErr))
	}

	creation, creationErr := fetchHeliusMintCreationObservation(ctx, endpoint, mint)
	if creationErr == nil && strings.TrimSpace(creation.Signature) != "" {
		out.Available = true
		out.CreateTransaction = strings.TrimSpace(creation.Signature)
		out.FirstMintTransaction = strings.TrimSpace(creation.Signature)
		out.CreatedTime = creation.BlockTime
		out.FirstMintTime = creation.BlockTime
		if creation.BlockTime > 0 {
			out.CreatedAt = time.Unix(creation.BlockTime, 0).UTC()
			out.FirstMintAt = out.CreatedAt
		}
		if out.Creator == "" {
			out.Creator = strings.TrimSpace(creation.Creator)
		}
	} else if creationErr != nil {
		out.Limitations = append(out.Limitations, "Helius mint-creation history failed: "+compactClusterError(creationErr))
	}

	if !out.Available {
		out.Status = "collection_failed"
		return out
	}
	if out.Creator == "" {
		out.Status = "metadata_without_creator"
		out.Limitations = append(out.Limitations, "Helius returned token metadata without a verified creator or creation-transaction signer candidate.")
		return out
	}
	out.Status = "complete"
	out.Limitations = append(out.Limitations, "Creator attribution is discovery-only and must be re-verified from canonical RPC before VERIFIED status.")
	return out
}

func fetchHeliusTokenAsset(ctx context.Context, endpoint, mint string) (heliusTokenMetadataResponse, error) {
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "koschei-token-metadata",
		"method":  "getAsset",
		"params": map[string]any{
			"id": strings.TrimSpace(mint),
			"options": map[string]any{
				"showFungible": true,
			},
		},
	})
	if err != nil {
		return heliusTokenMetadataResponse{}, err
	}
	responseBody, err := postHeliusRPC(ctx, endpoint, payload, 4<<20)
	if err != nil {
		return heliusTokenMetadataResponse{}, err
	}
	var response heliusTokenMetadataResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return heliusTokenMetadataResponse{}, fmt.Errorf("helius getAsset decode: %w", err)
	}
	if response.Error != nil {
		return heliusTokenMetadataResponse{}, fmt.Errorf("helius getAsset error %d: %s", response.Error.Code, strings.TrimSpace(response.Error.Message))
	}
	if strings.TrimSpace(response.Result.ID) == "" {
		return heliusTokenMetadataResponse{}, fmt.Errorf("helius getAsset returned no asset")
	}
	return response, nil
}

func fetchHeliusMintCreationObservation(ctx context.Context, endpoint, mint string) (heliusMintCreationObservation, error) {
	options := map[string]any{
		"transactionDetails":             "full",
		"sortOrder":                      "asc",
		"limit":                          20,
		"encoding":                       "jsonParsed",
		"maxSupportedTransactionVersion": 0,
		"filters": map[string]any{
			"status": "succeeded",
		},
	}
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "koschei-mint-creation",
		"method":  "getTransactionsForAddress",
		"params":  []any{strings.TrimSpace(mint), options},
	})
	if err != nil {
		return heliusMintCreationObservation{}, err
	}
	responseBody, err := postHeliusRPC(ctx, endpoint, payload, 16<<20)
	if err != nil {
		return heliusMintCreationObservation{}, err
	}
	var response heliusTransactionsForAddressResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return heliusMintCreationObservation{}, fmt.Errorf("helius mint history decode: %w", err)
	}
	if response.Error != nil {
		return heliusMintCreationObservation{}, fmt.Errorf("helius mint history error %d: %s", response.Error.Code, strings.TrimSpace(response.Error.Message))
	}
	for _, tx := range response.Result.Data {
		if observation, ok := extractMintCreationObservation(tx, mint); ok {
			return observation, nil
		}
	}
	return heliusMintCreationObservation{}, nil
}

func extractMintCreationObservation(tx map[string]any, expectedMint string) (heliusMintCreationObservation, bool) {
	message := createdMintMessage(tx)
	keys, signers := createdMintAccountKeys(message)
	for _, instruction := range createdMintInstructions(message, createdMintMap(tx["meta"])) {
		programID := strings.TrimSpace(firstCreatedMintString(instruction["programId"], instruction["program_id"]))
		programName := strings.ToLower(strings.TrimSpace(firstCreatedMintString(instruction["program"])))
		parsed := createdMintMap(instruction["parsed"])
		instructionType := strings.ToLower(strings.TrimSpace(firstCreatedMintString(parsed["type"], instruction["type"], instruction["instruction_type"])))
		info := createdMintMap(parsed["info"])
		mint := ""
		switch {
		case programID == canonicalPumpFunProgramID || strings.Contains(programName, "pump"):
			if instructionType != "" && !strings.Contains(instructionType, "create") {
				continue
			}
			mint = firstCreatedMintString(info["mint"], instruction["mint"])
			if mint == "" {
				accounts := createdMintInstructionAccounts(instruction, keys)
				if len(accounts) > 0 {
					mint = accounts[0]
				}
			}
		case programID == canonicalSPLTokenProgramID || programID == canonicalToken2022ProgramID || strings.Contains(programName, "token"):
			if instructionType != "initializemint" && instructionType != "initializemint2" && instructionType != "initialize_mint" && instructionType != "initialize_mint2" {
				continue
			}
			mint = firstCreatedMintString(info["mint"], instruction["mint"])
		default:
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(mint), strings.TrimSpace(expectedMint)) {
			continue
		}
		creator := ""
		for _, key := range keys {
			if signers[key] && !strings.EqualFold(key, expectedMint) {
				creator = key
				break
			}
		}
		return heliusMintCreationObservation{
			Creator: creator, Signature: createdMintSignature(tx),
			Slot:      createdMintInt64(tx["slot"]),
			BlockTime: createdMintInt64(firstCreatedMintValue(tx, "blockTime", "block_time")),
		}, true
	}
	return heliusMintCreationObservation{}, false
}

func verifiedHeliusAssetCreator(response heliusTokenMetadataResponse) string {
	for _, creator := range response.Result.Creators {
		if creator.Verified && strings.TrimSpace(creator.Address) != "" {
			return strings.TrimSpace(creator.Address)
		}
	}
	return ""
}

func firstNonEmptyHeliusMetadataString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func postHeliusRPC(ctx context.Context, endpoint string, payload []byte, maxBody int64) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("helius RPC status %d: %s", res.StatusCode, compactClusterError(fmt.Errorf("%s", strings.TrimSpace(string(body)))))
	}
	return body, nil
}
