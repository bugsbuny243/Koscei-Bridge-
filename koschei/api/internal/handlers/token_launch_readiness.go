package handlers

import (
	"context"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type tokenLaunchCheck struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Blocking bool   `json:"blocking"`
	Message  string `json:"message"`
}

func (h *Handler) PublicTokenLaunchReadiness(w http.ResponseWriter, r *http.Request) {
	checks := make([]tokenLaunchCheck, 0, 20)
	add := func(id, status, message string, blocking bool) {
		checks = append(checks, tokenLaunchCheck{ID: id, Status: status, Blocking: blocking, Message: message})
	}

	launchAtRaw := strings.TrimSpace(os.Getenv("KOSCHEI_TOKEN_LAUNCH_AT"))
	var launchAt *time.Time
	if launchAtRaw == "" {
		add("launch_time", "missing", "Launch time is not configured.", true)
	} else if parsed, err := time.Parse(time.RFC3339, launchAtRaw); err != nil {
		add("launch_time", "invalid", "Launch time must be RFC3339 with timezone.", true)
	} else {
		launchAt = &parsed
		if parsed.Before(time.Now().UTC()) {
			add("launch_time", "passed", "Configured launch time has passed.", true)
		} else {
			add("launch_time", "ready", "Launch time is configured.", false)
		}
	}

	name := strings.TrimSpace(os.Getenv("KOSCHEI_TOKEN_NAME"))
	symbol := strings.TrimSpace(os.Getenv("KOSCHEI_TOKEN_SYMBOL"))
	if name == "" || symbol == "" {
		add("identity", "missing", "Token name and symbol are required.", true)
	} else {
		add("identity", "ready", "Token identity is configured.", false)
	}

	network, networkOK := normalizeWalletNetwork(os.Getenv("KOSCHEI_TOKEN_NETWORK"))
	if !networkOK {
		add("network", "invalid", "Supported Solana network is required.", true)
	} else {
		add("network", "ready", "Solana network is configured.", false)
	}

	mint := strings.TrimSpace(os.Getenv("KOSCHEI_TOKEN_MINT"))
	mintValid := false
	if mint == "" {
		add("mint", "missing", "Official mint is not configured.", true)
	} else if _, err := decodeSolanaPublicKey(mint); err != nil {
		add("mint", "invalid", "Official mint is not a valid Solana public key.", true)
	} else {
		mintValid = true
		add("mint", "configured", "Official mint address is configured; on-chain verification follows.", false)
	}

	treasury := strings.TrimSpace(os.Getenv("KOSCHEI_TOKEN_TREASURY"))
	if treasury == "" {
		add("treasury", "missing", "Public treasury address is required.", true)
	} else if _, err := decodeSolanaPublicKey(treasury); err != nil {
		add("treasury", "invalid", "Treasury is not a valid Solana public key.", true)
	} else {
		add("treasury", "ready", "Public treasury address is configured.", false)
	}

	for _, item := range []struct {
		id       string
		env      string
		blocking bool
		label    string
	}{
		{"disclosure", "KOSCHEI_TOKEN_DISCLOSURE_URL", true, "risk disclosure"},
		{"vesting", "KOSCHEI_TOKEN_VESTING_URL", true, "vesting disclosure"},
		{"liquidity", "KOSCHEI_TOKEN_LIQUIDITY_LOCK_URL", false, "liquidity evidence"},
	} {
		value := strings.TrimSpace(os.Getenv(item.env))
		if value == "" {
			status := "warning"
			if item.blocking {
				status = "missing"
			}
			add(item.id, status, item.label+" URL is not configured.", item.blocking)
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			add(item.id, "invalid", item.label+" URL must be a valid HTTPS URL.", item.blocking)
			continue
		}
		add(item.id, "ready", item.label+" URL is configured.", false)
	}

	burnEnabled := strings.EqualFold(strings.TrimSpace(os.Getenv("KOSCHEI_TOKEN_BURN_ENABLED")), "true")
	if burnEnabled {
		add("burn", "blocked", "Automatic burn must remain disabled for launch.", true)
	} else {
		add("burn", "safe", "Automatic burn is disabled for launch.", false)
	}

	// KOSCH launch metadata may remain public/auditable, but holder thresholds
	// are permanently retired as a commercial authorization mechanism. Even if
	// an old environment flag remains set, it is ignored rather than reactivating
	// token-backed product access.
	legacyGateConfigured := strings.EqualFold(strings.TrimSpace(os.Getenv("KOSCHEI_TOKEN_GATE_ENABLED")), "true")
	if legacyGateConfigured {
		add("token_gate", "retired", "Legacy token-gate configuration is present but ignored; commercial access is SaaS-entitlement based.", false)
	} else {
		add("token_gate", "retired", "Token-backed commercial access is retired; commercial access is SaaS-entitlement based.", false)
	}

	if mintValid && networkOK {
		h.appendOnchainLaunchChecks(r.Context(), network, mint, &checks)
	}

	blocking := 0
	warnings := 0
	for _, check := range checks {
		if check.Blocking && check.Status != "ready" && check.Status != "safe" {
			blocking++
		}
		if !check.Blocking && (check.Status == "warning" || check.Status == "invalid") {
			warnings++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                           true,
		"launch_ready":                 blocking == 0,
		"blocking_count":               blocking,
		"warning_count":                warnings,
		"checks":                       checks,
		"generated_at":                 time.Now().UTC(),
		"launch_at":                    launchAt,
		"network":                      network,
		"mint":                         mint,
		"automatic_burn":               burnEnabled,
		"token_gate":                   false,
		"legacy_token_gate_configured": legacyGateConfigured,
		"commercial_access_model":      "saas_entitlement",
		"disclaimer":                   "Readiness means technical and disclosure gates passed; it does not predict price, demand or investment performance.",
	})
}

func (h *Handler) appendOnchainLaunchChecks(ctx context.Context, network, mint string, checks *[]tokenLaunchCheck) {
	add := func(id, status, message string, blocking bool) {
		*checks = append(*checks, tokenLaunchCheck{ID: id, Status: status, Blocking: blocking, Message: message})
	}
	if h == nil || h.SolanaRPC == nil {
		add("rpc", "unavailable", "Solana RPC is unavailable.", true)
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var account publicTokenMintResult
	if err := h.SolanaRPC.Call(ctx, network, "getAccountInfo", []any{mint, map[string]any{"encoding": "jsonParsed", "commitment": "confirmed"}}, &account, 15*time.Second); err != nil || account.Value == nil {
		add("mint_onchain", "unavailable", "Official mint could not be verified on-chain.", true)
		return
	}
	if account.Value.Data.Parsed.Type != "mint" {
		add("mint_onchain", "invalid", "Configured address is not a token mint.", true)
		return
	}
	if account.Value.Owner != legacySPLTokenProgramID && account.Value.Owner != token2022ProgramID {
		add("token_program", "invalid", "Mint is not owned by a supported token program.", true)
		return
	}
	add("mint_onchain", "ready", "Official mint is verified on-chain.", false)

	if account.Value.Data.Parsed.Info.MintAuthority != nil {
		add("mint_authority", "active", "Mint authority is still active.", true)
	} else {
		add("mint_authority", "revoked", "Mint authority is revoked.", false)
	}
	if account.Value.Data.Parsed.Info.FreezeAuthority != nil {
		add("freeze_authority", "active", "Freeze authority is still active.", true)
	} else {
		add("freeze_authority", "revoked", "Freeze authority is revoked.", false)
	}

	var supply publicTokenSupplyResult
	if err := h.SolanaRPC.Call(ctx, network, "getTokenSupply", []any{mint, map[string]any{"commitment": "confirmed"}}, &supply, 30*time.Second); err != nil {
		add("supply", "unavailable", "Token supply could not be verified.", true)
		return
	}
	raw := new(big.Int)
	if _, ok := raw.SetString(strings.TrimSpace(supply.Value.Amount), 10); !ok || raw.Sign() <= 0 {
		add("supply", "invalid", "Verified token supply is zero or invalid.", true)
		return
	}
	add("supply", "ready", "Token supply and decimals are verified on-chain.", false)
}
