package services

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const (
	piMainnetNetwork           = "pi-mainnet"
	piDefaultMainnetHorizonURL = "https://api.mainnet.minepi.com"
	piMainnetEvidenceSource    = "pi_mainnet_horizon"
	piTestnetEvidenceSourceV2  = "pi_testnet_horizon"
	piMainnetHorizonEnv        = "PI_MAINNET_HORIZON_URL"
	piTestnetHorizonEnv        = "PI_TESTNET_HORIZON_URL"
	piLegacyTestnetHorizonEnv  = "PI_HORIZON_URL"
)

func DefaultPiRadarNetwork() string { return piMainnetNetwork }

func NormalizePiRadarNetwork(network string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "pi", "pi-mainnet", "pinet-mainnet", "pi-network", "mainnet":
		return piMainnetNetwork, true
	case "pi-testnet", "pinet-testnet", "testnet":
		return piTestnetNetwork, true
	default:
		return "", false
	}
}

func PiRadarEvidenceSourceForNetwork(network string) string {
	if normalized, ok := NormalizePiRadarNetwork(network); ok && normalized == piTestnetNetwork {
		return piTestnetEvidenceSourceV2
	}
	return piMainnetEvidenceSource
}

func PiRadarNetworkLabel(network string) string {
	if normalized, ok := NormalizePiRadarNetwork(network); ok && normalized == piTestnetNetwork {
		return "Pi Testnet"
	}
	return "Pi Mainnet"
}

func piHorizonBaseURLForNetwork(network string) (*url.URL, error) {
	normalized, ok := NormalizePiRadarNetwork(network)
	if !ok {
		return nil, errors.New("unsupported Pi network")
	}
	envKey := piMainnetHorizonEnv
	fallback := piDefaultMainnetHorizonURL
	if normalized == piTestnetNetwork {
		envKey = piTestnetHorizonEnv
		fallback = piDefaultHorizonURL
	}
	raw := strings.TrimSpace(os.Getenv(envKey))
	if raw == "" && normalized == piTestnetNetwork {
		raw = strings.TrimSpace(os.Getenv(piLegacyTestnetHorizonEnv))
	}
	if raw == "" {
		raw = fallback
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid " + envKey)
	}
	if parsed.Scheme == "https" {
		parsed.Path = strings.TrimRight(parsed.Path, "/")
		return parsed, nil
	}
	if parsed.Scheme == "http" && piLoopbackHost(parsed.Hostname()) {
		parsed.Path = strings.TrimRight(parsed.Path, "/")
		return parsed, nil
	}
	return nil, errors.New(envKey + " must use HTTPS unless it is loopback test infrastructure")
}

func collectPiHorizonSnapshotForNetwork(ctx context.Context, target PiRadarTarget, network string) piHorizonSnapshot {
	normalized, ok := NormalizePiRadarNetwork(network)
	if !ok {
		normalized = DefaultPiRadarNetwork()
	}
	out := piHorizonSnapshot{Target: target, Source: PiRadarEvidenceSourceForNetwork(normalized), Errors: []string{}}
	base, err := piHorizonBaseURLForNetwork(normalized)
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
