package handlers

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const (
	piLaunchPreflightRuleset = "koschei-pi-testnet-launch-preflight-v1"
	piLaunchPreflightMaxBody = 64 << 10
)

var (
	piAssetCodePattern = regexp.MustCompile(`^[A-Za-z0-9]{1,12}$`)
	piAmountPattern    = regexp.MustCompile(`^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,7})?$`)
)

type piLaunchPreflightRequest struct {
	AssetCode     string `json:"asset_code"`
	InitialSupply string `json:"initial_supply"`
	Issuer        string `json:"issuer"`
	Distributor   string `json:"distributor"`
	IssuerName    string `json:"issuer_name"`
	Description   string `json:"description"`
	ImageURL      string `json:"image_url"`
	HomeDomain    string `json:"home_domain"`
	Utility       string `json:"utility"`
}

type piLaunchPreflightFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type piLaunchPreflightResponse struct {
	OK                    bool                       `json:"ok"`
	Product               string                     `json:"product"`
	Chain                 string                     `json:"chain"`
	Network               string                     `json:"network"`
	RulesetVersion        string                     `json:"ruleset_version"`
	Verdict               string                     `json:"verdict"`
	PlanHash              string                     `json:"plan_hash"`
	Findings              []piLaunchPreflightFinding `json:"findings"`
	CanMint               bool                       `json:"can_mint"`
	MainnetSupported      bool                       `json:"mainnet_supported"`
	RequiresWalletSecrets bool                       `json:"requires_wallet_secrets"`
	NextRequired          []string                   `json:"next_required"`
	Limitations           []string                   `json:"limitations"`
}

// PiLaunchPreflight validates a Pi Testnet token launch plan without taking
// custody of wallet secrets, signing transactions or submitting anything to
// the chain. It is deliberately narrower than token issuance.
func (h *Handler) PiLaunchPreflight(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, piLaunchPreflightMaxBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request piLaunchPreflightRequest
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid launch preflight request"})
		return
	}
	response := evaluatePiLaunchPreflight(request)
	writeJSON(w, http.StatusOK, response)
}

func evaluatePiLaunchPreflight(request piLaunchPreflightRequest) piLaunchPreflightResponse {
	request = normalizePiLaunchPreflightRequest(request)
	findings := make([]piLaunchPreflightFinding, 0, 10)
	blocking := false
	warnings := false

	add := func(code, severity, message string) {
		findings = append(findings, piLaunchPreflightFinding{Code: code, Severity: severity, Message: message})
		if severity == "block" {
			blocking = true
		}
		if severity == "warn" {
			warnings = true
		}
	}

	if !piAssetCodePattern.MatchString(request.AssetCode) {
		add("PI-ASSET-CODE", "block", "Asset code must be 1-12 case-sensitive alphanumeric characters.")
	} else {
		add("PI-ASSET-CODE", "pass", "Asset code matches the Pi Testnet token format.")
	}

	if !validPiLaunchAmount(request.InitialSupply) {
		add("PI-SUPPLY", "block", "Initial supply must be a positive decimal amount with at most seven fractional digits.")
	} else {
		add("PI-SUPPLY", "pass", "Initial supply is structurally valid.")
	}

	issuerOK := validStellarPublicKey(request.Issuer)
	distributorOK := validStellarPublicKey(request.Distributor)
	if !issuerOK {
		add("PI-ISSUER", "block", "Issuer must be a valid public G-address. Private keys are never accepted.")
	} else {
		add("PI-ISSUER", "pass", "Issuer public key checksum is valid.")
	}
	if !distributorOK {
		add("PI-DISTRIBUTOR", "block", "Distributor must be a valid public G-address. Private keys are never accepted.")
	} else {
		add("PI-DISTRIBUTOR", "pass", "Distributor public key checksum is valid.")
	}
	if issuerOK && distributorOK && request.Issuer == request.Distributor {
		add("PI-WALLET-SEPARATION", "block", "Issuer and distributor must be separate Pi Testnet wallets.")
	} else if issuerOK && distributorOK {
		add("PI-WALLET-SEPARATION", "pass", "Issuer and distributor are distinct public accounts.")
	}

	if request.IssuerName == "" || request.Description == "" || !validHTTPSURL(request.ImageURL) {
		add("PI-TOKEN-METADATA", "warn", "Pi Wallet verification metadata is incomplete: issuer_name, description and an HTTPS image URL are required for the planned pi.toml record.")
	} else {
		add("PI-TOKEN-METADATA", "pass", "Required token metadata fields are present for a future pi.toml record.")
	}

	if request.HomeDomain == "" {
		add("PI-HOME-DOMAIN", "warn", "No home domain is declared; Pi Wallet recognition requires the issuer account to bind a home domain and serve /.well-known/pi.toml.")
	} else if !validHomeDomain(request.HomeDomain) {
		add("PI-HOME-DOMAIN", "block", "Home domain must be a hostname only, without a path, query or scheme.")
	} else {
		add("PI-HOME-DOMAIN", "pass", "Home domain is structurally valid for issuer binding.")
	}

	if len(request.Utility) < 20 {
		add("PI-UTILITY", "warn", "Declare the token's concrete product utility; Pi's ecosystem-token model is product-first rather than speculation-first.")
	} else {
		add("PI-UTILITY", "pass", "A product-utility statement is present for review.")
	}

	verdict := "testnet_preflight_passed"
	if blocking {
		verdict = "blocked"
	} else if warnings {
		verdict = "testnet_preflight_passed_with_warnings"
	}

	return piLaunchPreflightResponse{
		OK:                    !blocking,
		Product:               "Koschei Forge",
		Chain:                 "pi",
		Network:               "pi-testnet",
		RulesetVersion:        piLaunchPreflightRuleset,
		Verdict:               verdict,
		PlanHash:              piLaunchPlanHash(request),
		Findings:              findings,
		CanMint:               false,
		MainnetSupported:      false,
		RequiresWalletSecrets: false,
		NextRequired: []string{
			"Pi Testnet distributor trustline authorization",
			"Pi Testnet issuer mint-payment authorization",
			"issuer home-domain binding and /.well-known/pi.toml publication for wallet recognition",
		},
		Limitations: []string{
			"This endpoint validates a launch plan; it does not create, sign or submit a token transaction.",
			"Koschei never requests, receives or stores Pi wallet private keys or passphrases.",
			"Pi Mainnet ecosystem-token issuance is outside this Testnet-only contract.",
		},
	}
}

func normalizePiLaunchPreflightRequest(request piLaunchPreflightRequest) piLaunchPreflightRequest {
	request.AssetCode = strings.TrimSpace(request.AssetCode)
	request.InitialSupply = strings.TrimSpace(request.InitialSupply)
	request.Issuer = strings.TrimSpace(request.Issuer)
	request.Distributor = strings.TrimSpace(request.Distributor)
	request.IssuerName = strings.TrimSpace(request.IssuerName)
	request.Description = strings.TrimSpace(request.Description)
	request.ImageURL = strings.TrimSpace(request.ImageURL)
	request.HomeDomain = strings.TrimSpace(strings.ToLower(request.HomeDomain))
	request.Utility = strings.TrimSpace(request.Utility)
	return request
}

func validPiLaunchAmount(value string) bool {
	if !piAmountPattern.MatchString(value) {
		return false
	}
	amount, ok := new(big.Rat).SetString(value)
	return ok && amount.Sign() > 0
}

func validHTTPSURL(value string) bool {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(value))
	return err == nil && parsed.Scheme == "https" && parsed.Host != ""
}

func validHomeDomain(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/?#:@") {
		return false
	}
	parsed, err := url.Parse("https://" + value)
	return err == nil && parsed.Hostname() == value && parsed.Port() == ""
}

func validStellarPublicKey(value string) bool {
	if len(value) != 56 || !strings.HasPrefix(value, "G") || value != strings.ToUpper(value) {
		return false
	}
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	raw, err := decoder.DecodeString(value)
	if err != nil || len(raw) != 35 || raw[0] != 6<<3 {
		return false
	}
	expected := uint16(raw[33]) | uint16(raw[34])<<8
	return crc16XModem(raw[:33]) == expected
}

func crc16XModem(data []byte) uint16 {
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

func piLaunchPlanHash(request piLaunchPreflightRequest) string {
	canonical := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		request.AssetCode,
		request.InitialSupply,
		request.Issuer,
		request.Distributor,
		request.IssuerName,
		request.Description,
		request.ImageURL,
		request.HomeDomain,
		request.Utility,
	)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}
