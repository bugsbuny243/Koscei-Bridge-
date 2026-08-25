package services

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	piTestnetNetwork             = "pi-testnet"
	piDefaultHorizonURL          = "https://api.testnet.minepi.com"
	piHorizonRequestTimeout      = 10 * time.Second
	piHorizonMaxResponseBytes    = 4 << 20
	piHorizonHolderPageLimit     = 200
	piHorizonMaxHolderPages      = 5
	piHorizonPaymentLimit        = 200
	piHorizonOperationLimit      = 100
	piHorizonTransactionLimit    = 100
	piHorizonLiquidityPoolLimit  = 200
	piRadarTargetKindAccount     = "account"
	piRadarTargetKindAsset       = "asset"
	piRadarEvidenceSourceHorizon = "pi_testnet_horizon"
)

type PiRadarTarget struct {
	Kind      string `json:"kind"`
	Raw       string `json:"raw"`
	Account   string `json:"account,omitempty"`
	AssetCode string `json:"asset_code,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
}

type piHorizonThresholds struct {
	LowThreshold  int `json:"low_threshold"`
	MedThreshold  int `json:"med_threshold"`
	HighThreshold int `json:"high_threshold"`
}

type piHorizonSigner struct {
	Key    string `json:"key"`
	Type   string `json:"type"`
	Weight int    `json:"weight"`
}

type piHorizonBalance struct {
	Balance      string `json:"balance"`
	AssetType    string `json:"asset_type"`
	AssetCode    string `json:"asset_code"`
	AssetIssuer  string `json:"asset_issuer"`
	Limit        string `json:"limit"`
	IsAuthorized bool   `json:"is_authorized"`
}

type piHorizonAccount struct {
	ID            string              `json:"id"`
	AccountID     string              `json:"account_id"`
	Sequence      string              `json:"sequence"`
	SubentryCount int                 `json:"subentry_count"`
	HomeDomain    string              `json:"home_domain"`
	Thresholds    piHorizonThresholds `json:"thresholds"`
	Signers       []piHorizonSigner   `json:"signers"`
	Balances      []piHorizonBalance  `json:"balances"`
}

type piHorizonPayment struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	TransactionHash string `json:"transaction_hash"`
	SourceAccount   string `json:"source_account"`
	From            string `json:"from"`
	To              string `json:"to"`
	AssetType       string `json:"asset_type"`
	AssetCode       string `json:"asset_code"`
	AssetIssuer     string `json:"asset_issuer"`
	Amount          string `json:"amount"`
	CreatedAt       string `json:"created_at"`
}

type piHorizonOperation struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	TransactionHash string `json:"transaction_hash"`
	SourceAccount   string `json:"source_account"`
	CreatedAt       string `json:"created_at"`
	HomeDomain      string `json:"home_domain"`
	SignerKey       string `json:"signer_key"`
	SignerWeight    int    `json:"signer_weight"`
	LowThreshold    int    `json:"low_threshold"`
	MedThreshold    int    `json:"med_threshold"`
	HighThreshold   int    `json:"high_threshold"`
}

type piHorizonTransaction struct {
	Hash           string `json:"hash"`
	Ledger         int64  `json:"ledger"`
	CreatedAt      string `json:"created_at"`
	SourceAccount  string `json:"source_account"`
	OperationCount int    `json:"operation_count"`
	Successful     bool   `json:"successful"`
	FeeCharged     string `json:"fee_charged"`
	MaxFee         string `json:"max_fee"`
}

type piHorizonLink struct {
	Href string `json:"href"`
}

type piHorizonPageLinks struct {
	Next piHorizonLink `json:"next"`
}

type piHorizonAccountPage struct {
	Links    piHorizonPageLinks `json:"_links"`
	Embedded struct {
		Records []piHorizonAccount `json:"records"`
	} `json:"_embedded"`
}

type piHorizonPaymentPage struct {
	Embedded struct {
		Records []piHorizonPayment `json:"records"`
	} `json:"_embedded"`
}

type piHorizonOperationPage struct {
	Embedded struct {
		Records []piHorizonOperation `json:"records"`
	} `json:"_embedded"`
}

type piHorizonTransactionPage struct {
	Embedded struct {
		Records []piHorizonTransaction `json:"records"`
	} `json:"_embedded"`
}

type piHorizonAssetPage struct {
	Embedded struct {
		Records []map[string]any `json:"records"`
	} `json:"_embedded"`
}

type piHorizonLiquidityPoolPage struct {
	Embedded struct {
		Records []map[string]any `json:"records"`
	} `json:"_embedded"`
}

type piHolderObservation struct {
	Account    string  `json:"account"`
	Balance    float64 `json:"balance"`
	Authorized bool    `json:"authorized"`
}

type piHorizonSnapshot struct {
	Target                   PiRadarTarget          `json:"target"`
	Source                   string                 `json:"source"`
	Available                bool                   `json:"available"`
	AssetFound               bool                   `json:"asset_found"`
	IssuerAccount            *piHorizonAccount      `json:"issuer_account,omitempty"`
	WalletAccount            *piHorizonAccount      `json:"wallet_account,omitempty"`
	AssetRecord              map[string]any         `json:"asset_record,omitempty"`
	Holders                  []piHolderObservation  `json:"holders,omitempty"`
	HolderPagesFetched       int                    `json:"holder_pages_fetched"`
	HolderWindowComplete     bool                   `json:"holder_window_complete"`
	IssuerPayments           []piHorizonPayment     `json:"issuer_payments,omitempty"`
	IssuerOperations         []piHorizonOperation   `json:"issuer_operations,omitempty"`
	IssuerTransactions       []piHorizonTransaction `json:"issuer_transactions,omitempty"`
	LiquidityPools           []map[string]any       `json:"liquidity_pools,omitempty"`
	LiquidityQuerySuccessful bool                   `json:"liquidity_query_successful"`
	Errors                   []string               `json:"errors,omitempty"`
}

func ParsePiRadarTarget(raw string) (PiRadarTarget, bool) {
	value := strings.TrimSpace(raw)
	if validPiPublicKey(value) {
		return PiRadarTarget{Kind: piRadarTargetKindAccount, Raw: value, Account: value}, true
	}
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return PiRadarTarget{}, false
	}
	code := strings.TrimSpace(parts[0])
	issuer := strings.TrimSpace(parts[1])
	if !validPiAssetCode(code) || !validPiPublicKey(issuer) {
		return PiRadarTarget{}, false
	}
	return PiRadarTarget{Kind: piRadarTargetKindAsset, Raw: value, AssetCode: code, Issuer: issuer}, true
}

func IsPiRadarNetwork(network string) bool {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "pi", "pi-testnet", "pinet-testnet":
		return true
	default:
		return false
	}
}

func validPiAssetCode(code string) bool {
	if len(code) < 1 || len(code) > 12 {
		return false
	}
	for _, r := range code {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

func validPiPublicKey(value string) bool {
	if len(value) != 56 || !strings.HasPrefix(value, "G") || value != strings.ToUpper(value) {
		return false
	}
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	raw, err := decoder.DecodeString(value)
	if err != nil || len(raw) != 35 || raw[0] != 6<<3 {
		return false
	}
	expected := uint16(raw[33]) | uint16(raw[34])<<8
	return piCRC16XModem(raw[:33]) == expected
}

func piCRC16XModem(data []byte) uint16 {
	var crc uint16
	for _, item := range data {
		crc ^= uint16(item) << 8
		for bit := 0; bit < 8; bit++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func collectPiHorizonSnapshot(ctx context.Context, target PiRadarTarget) piHorizonSnapshot {
	out := piHorizonSnapshot{Target: target, Source: piRadarEvidenceSourceHorizon, Errors: []string{}}
	base, err := piHorizonBaseURL()
	if err != nil {
		out.Errors = append(out.Errors, err.Error())
		return out
	}
	client := &http.Client{Timeout: piHorizonRequestTimeout}

	if target.Kind == piRadarTargetKindAccount {
		var account piHorizonAccount
		if err := piHorizonGetJSON(ctx, client, base, "/accounts/"+url.PathEscape(target.Account), nil, &account); err != nil {
			out.Errors = append(out.Errors, "account: "+compactPiHorizonError(err))
			return out
		}
		out.WalletAccount = &account
		out.Available = true
		return out
	}

	var issuer piHorizonAccount
	if err := piHorizonGetJSON(ctx, client, base, "/accounts/"+url.PathEscape(target.Issuer), nil, &issuer); err != nil {
		out.Errors = append(out.Errors, "issuer_account: "+compactPiHorizonError(err))
	} else {
		out.IssuerAccount = &issuer
		out.Available = true
	}

	assetQuery := url.Values{"asset_code": []string{target.AssetCode}, "asset_issuer": []string{target.Issuer}, "limit": []string{"10"}}
	var assetPage piHorizonAssetPage
	if err := piHorizonGetJSON(ctx, client, base, "/assets", assetQuery, &assetPage); err != nil {
		out.Errors = append(out.Errors, "asset: "+compactPiHorizonError(err))
	} else {
		for _, record := range assetPage.Embedded.Records {
			if piMapString(record, "asset_code") == target.AssetCode && piMapString(record, "asset_issuer") == target.Issuer {
				out.AssetRecord = record
				out.AssetFound = true
				out.Available = true
				break
			}
		}
	}

	holders, pages, complete, holderErr := collectPiAssetHolders(ctx, client, base, target)
	out.Holders, out.HolderPagesFetched, out.HolderWindowComplete = holders, pages, complete
	if holderErr != nil {
		out.Errors = append(out.Errors, "holders: "+compactPiHorizonError(holderErr))
	}

	paymentsQuery := url.Values{"order": []string{"asc"}, "limit": []string{strconv.Itoa(piHorizonPaymentLimit)}}
	var paymentPage piHorizonPaymentPage
	if err := piHorizonGetJSON(ctx, client, base, "/accounts/"+url.PathEscape(target.Issuer)+"/payments", paymentsQuery, &paymentPage); err != nil {
		out.Errors = append(out.Errors, "issuer_payments: "+compactPiHorizonError(err))
	} else {
		for _, payment := range paymentPage.Embedded.Records {
			if strings.EqualFold(payment.Type, "payment") && payment.AssetCode == target.AssetCode && payment.AssetIssuer == target.Issuer && (payment.From == target.Issuer || payment.SourceAccount == target.Issuer) {
				out.IssuerPayments = append(out.IssuerPayments, payment)
			}
		}
	}

	operationsQuery := url.Values{"order": []string{"desc"}, "limit": []string{strconv.Itoa(piHorizonOperationLimit)}}
	var operationPage piHorizonOperationPage
	if err := piHorizonGetJSON(ctx, client, base, "/accounts/"+url.PathEscape(target.Issuer)+"/operations", operationsQuery, &operationPage); err != nil {
		out.Errors = append(out.Errors, "issuer_operations: "+compactPiHorizonError(err))
	} else {
		out.IssuerOperations = append(out.IssuerOperations, operationPage.Embedded.Records...)
	}

	transactionsQuery := url.Values{"order": []string{"desc"}, "limit": []string{strconv.Itoa(piHorizonTransactionLimit)}, "include_failed": []string{"true"}}
	var transactionPage piHorizonTransactionPage
	if err := piHorizonGetJSON(ctx, client, base, "/accounts/"+url.PathEscape(target.Issuer)+"/transactions", transactionsQuery, &transactionPage); err != nil {
		out.Errors = append(out.Errors, "issuer_transactions: "+compactPiHorizonError(err))
	} else {
		out.IssuerTransactions = append(out.IssuerTransactions, transactionPage.Embedded.Records...)
	}

	liquidityQuery := url.Values{"reserves": []string{"native," + target.AssetCode + ":" + target.Issuer}, "limit": []string{strconv.Itoa(piHorizonLiquidityPoolLimit)}}
	var liquidityPage piHorizonLiquidityPoolPage
	if err := piHorizonGetJSON(ctx, client, base, "/liquidity_pools", liquidityQuery, &liquidityPage); err != nil {
		out.Errors = append(out.Errors, "liquidity_pools: "+compactPiHorizonError(err))
	} else {
		out.LiquidityQuerySuccessful = true
		out.LiquidityPools = append(out.LiquidityPools, liquidityPage.Embedded.Records...)
	}
	return out
}

func collectPiAssetHolders(ctx context.Context, client *http.Client, base *url.URL, target PiRadarTarget) ([]piHolderObservation, int, bool, error) {
	query := url.Values{"asset": []string{target.AssetCode + ":" + target.Issuer}, "limit": []string{strconv.Itoa(piHorizonHolderPageLimit)}, "order": []string{"asc"}}
	nextPath := "/accounts"
	var holders []piHolderObservation
	seenNext := map[string]bool{}
	for page := 0; page < piHorizonMaxHolderPages; page++ {
		var response piHorizonAccountPage
		if err := piHorizonGetJSON(ctx, client, base, nextPath, query, &response); err != nil {
			return holders, page, false, err
		}
		for _, account := range response.Embedded.Records {
			for _, balance := range account.Balances {
				if balance.AssetCode != target.AssetCode || balance.AssetIssuer != target.Issuer {
					continue
				}
				amount, err := strconv.ParseFloat(balance.Balance, 64)
				if err != nil || amount < 0 {
					continue
				}
				accountID := strings.TrimSpace(account.AccountID)
				if accountID == "" {
					accountID = strings.TrimSpace(account.ID)
				}
				holders = append(holders, piHolderObservation{Account: accountID, Balance: amount, Authorized: balance.IsAuthorized})
				break
			}
		}
		next := strings.TrimSpace(response.Links.Next.Href)
		if next == "" || len(response.Embedded.Records) < piHorizonHolderPageLimit {
			return holders, page + 1, true, nil
		}
		if seenNext[next] {
			return holders, page + 1, false, errors.New("repeated Horizon pagination cursor")
		}
		seenNext[next] = true
		parsed, err := url.Parse(next)
		if err != nil || !samePiHorizonOrigin(base, parsed) {
			return holders, page + 1, false, errors.New("unsafe Horizon pagination URL")
		}
		nextPath = parsed.Path
		query = parsed.Query()
	}
	return holders, piHorizonMaxHolderPages, false, nil
}

func piHorizonBaseURL() (*url.URL, error) {
	raw := strings.TrimSpace(os.Getenv("PI_HORIZON_URL"))
	if raw == "" {
		raw = piDefaultHorizonURL
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid PI_HORIZON_URL")
	}
	if parsed.Scheme == "https" {
		parsed.Path = strings.TrimRight(parsed.Path, "/")
		return parsed, nil
	}
	if parsed.Scheme == "http" && piLoopbackHost(parsed.Hostname()) {
		parsed.Path = strings.TrimRight(parsed.Path, "/")
		return parsed, nil
	}
	return nil, errors.New("PI_HORIZON_URL must use HTTPS unless it is loopback test infrastructure")
}

func piLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func piHorizonGetJSON(ctx context.Context, client *http.Client, base *url.URL, path string, query url.Values, out any) error {
	if client == nil || base == nil {
		return errors.New("Pi Horizon client is unavailable")
	}
	requestURL := *base
	basePath := strings.TrimRight(base.Path, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	requestURL.Path = basePath + path
	requestURL.RawQuery = query.Encode()
	requestCtx, cancel := context.WithTimeout(ctx, piHorizonRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/hal+json, application/json")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, piHorizonMaxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(body) > piHorizonMaxResponseBytes {
		return errors.New("Pi Horizon response exceeded bounded size")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("Pi Horizon status %d", res.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("Pi Horizon JSON decode: %w", err)
	}
	return nil
}

func samePiHorizonOrigin(base, candidate *url.URL) bool {
	if base == nil || candidate == nil {
		return false
	}
	return strings.EqualFold(base.Scheme, candidate.Scheme) && strings.EqualFold(base.Host, candidate.Host) && candidate.User == nil
}

func piMapString(record map[string]any, key string) string {
	if record == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(record[key]))
}

func compactPiHorizonError(err error) string {
	value := strings.TrimSpace(fmt.Sprint(err))
	if len(value) > 240 {
		value = value[:240]
	}
	return value
}
