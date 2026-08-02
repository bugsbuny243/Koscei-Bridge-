package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const defaultSolscanAPIBaseURL = "https://pro-api.solscan.io/v2.0"

type SolscanFundedBy struct {
	Wallet     string    `json:"wallet,omitempty"`
	Signature  string    `json:"signature,omitempty"`
	BlockTime  int64     `json:"block_time,omitempty"`
	ObservedAt time.Time `json:"observed_at,omitempty"`
}

type SolscanAccountMetadata struct {
	Available      bool            `json:"available"`
	AccountAddress string          `json:"account_address,omitempty"`
	Label          string          `json:"label,omitempty"`
	Icon           string          `json:"icon,omitempty"`
	Tags           []string        `json:"tags"`
	AccountType    string          `json:"account_type,omitempty"`
	Domain         string          `json:"domain,omitempty"`
	ActiveAgeDays  int64           `json:"active_age_days,omitempty"`
	FundedBy       SolscanFundedBy `json:"funded_by"`
}

type SolscanAccountTransaction struct {
	Slot               int64           `json:"slot,omitempty"`
	Fee                int64           `json:"fee,omitempty"`
	Status             string          `json:"status,omitempty"`
	Signer             json.RawMessage `json:"signer,omitempty"`
	BlockTime          int64           `json:"block_time,omitempty"`
	Signature          string          `json:"signature"`
	ProgramIDs         json.RawMessage `json:"program_ids,omitempty"`
	ParsedInstructions json.RawMessage `json:"parsed_instructions,omitempty"`
}

type SolscanTokenAccountObservation struct {
	TokenAccount string `json:"token_account"`
	Mint         string `json:"mint"`
	AmountRaw    string `json:"amount_raw,omitempty"`
	Decimals     int    `json:"decimals,omitempty"`
	Owner        string `json:"owner,omitempty"`
}

type SolscanActorDiscovery struct {
	Configured            bool                             `json:"configured"`
	Available             bool                             `json:"available"`
	Status                string                           `json:"status"`
	Provider              string                           `json:"provider"`
	Wallet                string                           `json:"wallet"`
	Metadata              SolscanAccountMetadata           `json:"metadata"`
	TransactionCandidates []SolscanAccountTransaction      `json:"transaction_candidates"`
	TokenAccounts         []SolscanTokenAccountObservation `json:"token_accounts"`
	EndpointStatus        map[string]string                `json:"endpoint_status"`
	ObservedAt            time.Time                        `json:"observed_at"`
	Limitations           []string                         `json:"limitations"`
}

type SolscanClient struct {
	APIKey  string
	BaseURL string
	Client  *http.Client
}

type solscanResponse[T any] struct {
	Success bool `json:"success"`
	Data    T    `json:"data"`
	Errors  struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

type solscanMetadataPayload struct {
	AccountAddress string   `json:"account_address"`
	AccountLabel   string   `json:"account_label"`
	AccountIcon    string   `json:"account_icon"`
	AccountTags    []string `json:"account_tags"`
	AccountType    string   `json:"account_type"`
	AccountDomain  string   `json:"account_domain"`
	ActiveAge      int64    `json:"active_age"`
	FundedBy       struct {
		FundedBy  string `json:"funded_by"`
		TxHash    string `json:"tx_hash"`
		BlockTime int64  `json:"block_time"`
	} `json:"funded_by"`
}

type solscanTransactionPayload struct {
	Slot               int64           `json:"slot"`
	Fee                int64           `json:"fee"`
	Status             string          `json:"status"`
	Signer             json.RawMessage `json:"signer"`
	BlockTime          int64           `json:"block_time"`
	TxHash             string          `json:"tx_hash"`
	ProgramIDs         json.RawMessage `json:"program_ids"`
	ParsedInstructions json.RawMessage `json:"parsed_instructions"`
}

type solscanTokenAccountPayload struct {
	TokenAccount  string      `json:"token_account"`
	TokenAddress  string      `json:"token_address"`
	Amount        json.Number `json:"amount"`
	AmountString  string      `json:"amount_str"`
	TokenDecimals int         `json:"token_decimals"`
	Owner         string      `json:"owner"`
}

func NewSolscanClientFromEnv() *SolscanClient {
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("SOLSCAN_API_BASE_URL")), "/")
	if baseURL == "" {
		baseURL = defaultSolscanAPIBaseURL
	}
	timeoutSeconds := solscanEnvInt("SOLSCAN_API_TIMEOUT_SECONDS", 12, 3, 60)
	return &SolscanClient{
		APIKey:  strings.TrimSpace(os.Getenv("SOLSCAN_API_KEY")),
		BaseURL: baseURL,
		Client:  &http.Client{Timeout: time.Duration(timeoutSeconds) * time.Second},
	}
}

func FetchSolscanActorDiscovery(ctx context.Context, wallet string, transactionLimit int) SolscanActorDiscovery {
	return NewSolscanClientFromEnv().DiscoverActor(ctx, wallet, transactionLimit)
}

func (c *SolscanClient) DiscoverActor(ctx context.Context, wallet string, transactionLimit int) SolscanActorDiscovery {
	wallet = strings.TrimSpace(wallet)
	out := SolscanActorDiscovery{
		Configured: strings.TrimSpace(c.APIKey) != "",
		Status:     "not_configured", Provider: "solscan_pro_api_v2", Wallet: wallet,
		Metadata:              SolscanAccountMetadata{Tags: []string{}},
		TransactionCandidates: []SolscanAccountTransaction{},
		TokenAccounts:         []SolscanTokenAccountObservation{},
		EndpointStatus:        map[string]string{}, ObservedAt: time.Now().UTC(), Limitations: []string{},
	}
	if wallet == "" {
		out.Status = "wallet_required"
		out.Limitations = append(out.Limitations, "A wallet address is required for Solscan actor discovery.")
		return out
	}
	if !out.Configured {
		out.Limitations = append(out.Limitations, "SOLSCAN_API_KEY is not configured; external attribution discovery was skipped.")
		return out
	}
	if transactionLimit <= 0 {
		transactionLimit = 40
	}
	transactionLimit = normalizeSolscanTransactionLimit(transactionLimit)

	successCount := 0
	if metadata, err := c.fetchMetadata(ctx, wallet); err == nil {
		out.Metadata = metadata
		out.EndpointStatus["account_metadata"] = "complete"
		successCount++
	} else {
		out.EndpointStatus["account_metadata"] = "failed"
		out.Limitations = append(out.Limitations, "Solscan account metadata could not be collected: "+compactSolscanError(err))
	}
	if transactions, err := c.fetchTransactions(ctx, wallet, transactionLimit); err == nil {
		out.TransactionCandidates = transactions
		out.EndpointStatus["account_transactions"] = "complete"
		successCount++
	} else {
		out.EndpointStatus["account_transactions"] = "failed"
		out.Limitations = append(out.Limitations, "Solscan account transaction candidates could not be collected: "+compactSolscanError(err))
	}
	if tokenAccounts, err := c.fetchTokenAccounts(ctx, wallet); err == nil {
		out.TokenAccounts = tokenAccounts
		out.EndpointStatus["account_token_accounts"] = "complete"
		successCount++
	} else {
		out.EndpointStatus["account_token_accounts"] = "failed"
		out.Limitations = append(out.Limitations, "Solscan token-account inventory could not be collected: "+compactSolscanError(err))
	}

	out.Available = successCount > 0
	switch successCount {
	case 3:
		out.Status = "complete"
	case 0:
		out.Status = "collection_failed"
	default:
		out.Status = "partial"
	}
	return out
}

func (c *SolscanClient) fetchMetadata(ctx context.Context, wallet string) (SolscanAccountMetadata, error) {
	var response solscanResponse[solscanMetadataPayload]
	if err := c.get(ctx, "/account/metadata", url.Values{"address": []string{wallet}}, &response); err != nil {
		return SolscanAccountMetadata{}, err
	}
	if !response.Success {
		return SolscanAccountMetadata{}, fmt.Errorf("solscan metadata response unsuccessful: %s", strings.TrimSpace(response.Errors.Message))
	}
	payload := response.Data
	fundedAt := time.Time{}
	if payload.FundedBy.BlockTime > 0 {
		fundedAt = time.Unix(payload.FundedBy.BlockTime, 0).UTC()
	}
	return SolscanAccountMetadata{
		Available:      true,
		AccountAddress: strings.TrimSpace(payload.AccountAddress),
		Label:          strings.TrimSpace(payload.AccountLabel),
		Icon:           strings.TrimSpace(payload.AccountIcon),
		Tags:           normalizeSolscanStrings(payload.AccountTags),
		AccountType:    strings.TrimSpace(payload.AccountType),
		Domain:         strings.TrimSpace(payload.AccountDomain),
		ActiveAgeDays:  payload.ActiveAge,
		FundedBy: SolscanFundedBy{
			Wallet:     strings.TrimSpace(payload.FundedBy.FundedBy),
			Signature:  strings.TrimSpace(payload.FundedBy.TxHash),
			BlockTime:  payload.FundedBy.BlockTime,
			ObservedAt: fundedAt,
		},
	}, nil
}

func (c *SolscanClient) fetchTransactions(ctx context.Context, wallet string, limit int) ([]SolscanAccountTransaction, error) {
	var response solscanResponse[[]solscanTransactionPayload]
	params := url.Values{"address": []string{wallet}, "limit": []string{strconv.Itoa(normalizeSolscanTransactionLimit(limit))}}
	if err := c.get(ctx, "/account/transactions", params, &response); err != nil {
		return nil, err
	}
	if !response.Success {
		return nil, fmt.Errorf("solscan transactions response unsuccessful: %s", strings.TrimSpace(response.Errors.Message))
	}
	out := make([]SolscanAccountTransaction, 0, len(response.Data))
	for _, row := range response.Data {
		signature := strings.TrimSpace(row.TxHash)
		if signature == "" {
			continue
		}
		out = append(out, SolscanAccountTransaction{
			Slot: row.Slot, Fee: row.Fee, Status: strings.TrimSpace(row.Status), Signer: row.Signer,
			BlockTime: row.BlockTime, Signature: signature, ProgramIDs: row.ProgramIDs,
			ParsedInstructions: row.ParsedInstructions,
		})
	}
	return out, nil
}

func (c *SolscanClient) fetchTokenAccounts(ctx context.Context, wallet string) ([]SolscanTokenAccountObservation, error) {
	var response solscanResponse[[]solscanTokenAccountPayload]
	if err := c.get(ctx, "/account/token-accounts", url.Values{"address": []string{wallet}}, &response); err != nil {
		return nil, err
	}
	if !response.Success {
		return nil, fmt.Errorf("solscan token-account response unsuccessful: %s", strings.TrimSpace(response.Errors.Message))
	}
	out := make([]SolscanTokenAccountObservation, 0, len(response.Data))
	seen := map[string]bool{}
	for _, row := range response.Data {
		tokenAccount := strings.TrimSpace(row.TokenAccount)
		mint := strings.TrimSpace(row.TokenAddress)
		if tokenAccount == "" || mint == "" || seen[tokenAccount] {
			continue
		}
		seen[tokenAccount] = true
		amount := strings.TrimSpace(row.AmountString)
		if amount == "" {
			amount = strings.TrimSpace(row.Amount.String())
		}
		out = append(out, SolscanTokenAccountObservation{
			TokenAccount: tokenAccount, Mint: mint, AmountRaw: amount,
			Decimals: row.TokenDecimals, Owner: strings.TrimSpace(row.Owner),
		})
		if len(out) >= 250 {
			break
		}
	}
	return out, nil
}

func (c *SolscanClient) get(ctx context.Context, path string, params url.Values, out any) error {
	if c == nil {
		return fmt.Errorf("solscan client is nil")
	}
	apiKey := strings.TrimSpace(c.APIKey)
	if apiKey == "" {
		return fmt.Errorf("solscan api key is not configured")
	}
	baseURL := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if baseURL == "" {
		baseURL = defaultSolscanAPIBaseURL
	}
	endpoint := baseURL + "/" + strings.TrimLeft(path, "/")
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("token", apiKey)
	req.Header.Set("User-Agent", "Koschei-Actor-Investigation/1.0")
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 12 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("solscan http status %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return err
	}
	return nil
}

func SolscanActorDiscoveryEvidence(discovery SolscanActorDiscovery, network string) []ActorDefenseEvidenceRecord {
	wallet := strings.TrimSpace(discovery.Wallet)
	if wallet == "" || !discovery.Available {
		return []ActorDefenseEvidenceRecord{}
	}
	network = normalizeRadarNetwork(network)
	now := discovery.ObservedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	out := []ActorDefenseEvidenceRecord{}
	metadata := discovery.Metadata
	if metadata.Available && (metadata.Label != "" || len(metadata.Tags) > 0 || metadata.AccountType != "") {
		out = append(out, ActorDefenseEvidenceRecord{
			Network: network, ActorWallet: wallet,
			CounterpartKind: "external_attribution", CounterpartID: wallet,
			Relation: "external_account_attribution", VerificationStatus: "observed",
			EvidenceKey: "solscan:account_metadata:" + wallet, Source: "solscan_pro_api_v2",
			ObservedAt: now, OccurrenceCount: 1,
			Metadata: map[string]any{
				"label": metadata.Label, "tags": metadata.Tags, "account_type": metadata.AccountType,
				"domain": metadata.Domain, "active_age_days": metadata.ActiveAgeDays,
				"external_attribution_only": true, "identity_or_wrongdoing_claim": false,
			},
		})
	}
	if funder := strings.TrimSpace(metadata.FundedBy.Wallet); funder != "" {
		observedAt := metadata.FundedBy.ObservedAt
		if observedAt.IsZero() {
			observedAt = now
		}
		out = append(out, ActorDefenseEvidenceRecord{
			Network: network, ActorWallet: wallet,
			CounterpartKind: "wallet", CounterpartID: funder,
			Relation: "external_funding_attribution", VerificationStatus: "observed",
			EvidenceKey: "solscan:funded_by:" + wallet + ":" + funder,
			Source:      "solscan_pro_api_v2", Signature: strings.TrimSpace(metadata.FundedBy.Signature),
			ObservedAt: observedAt, OccurrenceCount: 1,
			Metadata: map[string]any{
				"source_wallet": funder, "destination_wallet": wallet,
				"external_attribution_only":           true,
				"requires_rpc_signature_verification": true,
				"identity_or_wrongdoing_claim":        false,
			},
		})
	}
	for _, tokenAccount := range discovery.TokenAccounts {
		mint := strings.TrimSpace(tokenAccount.Mint)
		account := strings.TrimSpace(tokenAccount.TokenAccount)
		if mint == "" || account == "" {
			continue
		}
		out = append(out, ActorDefenseEvidenceRecord{
			Network: network, ActorWallet: wallet,
			CounterpartKind: "token", CounterpartID: mint,
			Relation: "external_token_account_observation", VerificationStatus: "observed",
			EvidenceKey: "solscan:token_account:" + account,
			Source:      "solscan_pro_api_v2", ObservedAt: now, TokenMint: mint, OccurrenceCount: 1,
			Metadata: map[string]any{
				"token_account": account, "amount_raw": tokenAccount.AmountRaw,
				"decimals": tokenAccount.Decimals, "reported_owner": tokenAccount.Owner,
				"does_not_prove_token_creation": true,
			},
		})
		if len(out) >= 52 {
			break
		}
	}
	return out
}

func normalizeSolscanTransactionLimit(limit int) int {
	switch {
	case limit <= 10:
		return 10
	case limit <= 20:
		return 20
	case limit <= 30:
		return 30
	default:
		return 40
	}
}

func normalizeSolscanStrings(values []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func compactSolscanError(err error) string {
	if err == nil {
		return "unknown error"
	}
	value := strings.TrimSpace(err.Error())
	if len(value) > 220 {
		value = value[:220]
	}
	return value
}

func solscanEnvInt(name string, fallback, minValue, maxValue int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil {
		return fallback
	}
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
