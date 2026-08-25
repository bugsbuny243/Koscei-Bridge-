package handlers

import (
	"encoding/base32"
	"strings"
	"testing"
)

func TestPiLaunchPreflightPassesCompleteTestnetPlan(t *testing.T) {
	request := piLaunchPreflightRequest{
		AssetCode:     "KSAFE",
		InitialSupply: "1000000",
		Issuer:        piLaunchTestPublicKey(0x11),
		Distributor:   piLaunchTestPublicKey(0x22),
		IssuerName:    "Koschei Test Issuer",
		Description:   "A Testnet utility token used to validate Koschei launch evidence.",
		ImageURL:      "https://tradepigloball.co/assets/koschei-token.png",
		HomeDomain:    "tradepigloball.co",
		Utility:       "Access to a Testnet-only launch validation workflow and security evidence.",
	}
	response := evaluatePiLaunchPreflight(request)
	if !response.OK || response.Verdict != "testnet_preflight_passed" {
		t.Fatalf("unexpected response: %#v", response)
	}
	if response.CanMint || response.MainnetSupported || response.RequiresWalletSecrets {
		t.Fatalf("unsafe authority surfaced: %#v", response)
	}
	if len(response.PlanHash) != 64 {
		t.Fatalf("plan hash=%q", response.PlanHash)
	}
}

func TestPiLaunchPreflightRejectsSecretOrInvalidPublicKeyShape(t *testing.T) {
	request := piLaunchPreflightRequest{
		AssetCode:     "SAFE",
		InitialSupply: "10",
		Issuer:        "S" + strings.Repeat("A", 55),
		Distributor:   piLaunchTestPublicKey(0x22),
	}
	response := evaluatePiLaunchPreflight(request)
	if response.OK || response.Verdict != "blocked" {
		t.Fatalf("secret-looking issuer was not blocked: %#v", response)
	}
	if !piLaunchHasFinding(response, "PI-ISSUER", "block") {
		t.Fatalf("issuer block finding missing: %#v", response.Findings)
	}
}

func TestPiLaunchPreflightRequiresSeparateIssuerAndDistributor(t *testing.T) {
	key := piLaunchTestPublicKey(0x33)
	response := evaluatePiLaunchPreflight(piLaunchPreflightRequest{
		AssetCode:     "SAFE",
		InitialSupply: "100",
		Issuer:        key,
		Distributor:   key,
	})
	if response.OK || !piLaunchHasFinding(response, "PI-WALLET-SEPARATION", "block") {
		t.Fatalf("same issuer/distributor was not blocked: %#v", response)
	}
}

func TestPiLaunchPreflightMetadataAndUtilityStayWarnings(t *testing.T) {
	response := evaluatePiLaunchPreflight(piLaunchPreflightRequest{
		AssetCode:     "SAFE",
		InitialSupply: "100",
		Issuer:        piLaunchTestPublicKey(0x44),
		Distributor:   piLaunchTestPublicKey(0x55),
	})
	if !response.OK || response.Verdict != "testnet_preflight_passed_with_warnings" {
		t.Fatalf("warnings should not fabricate a block: %#v", response)
	}
	if !piLaunchHasFinding(response, "PI-TOKEN-METADATA", "warn") || !piLaunchHasFinding(response, "PI-UTILITY", "warn") {
		t.Fatalf("expected warnings missing: %#v", response.Findings)
	}
}

func TestPiLaunchPreflightRejectsMalformedAmountAndDomain(t *testing.T) {
	response := evaluatePiLaunchPreflight(piLaunchPreflightRequest{
		AssetCode:     "SAFE",
		InitialSupply: "1.12345678",
		Issuer:        piLaunchTestPublicKey(0x66),
		Distributor:   piLaunchTestPublicKey(0x77),
		HomeDomain:    "https://tradepigloball.co/path",
	})
	if response.OK {
		t.Fatalf("invalid plan passed: %#v", response)
	}
	if !piLaunchHasFinding(response, "PI-SUPPLY", "block") || !piLaunchHasFinding(response, "PI-HOME-DOMAIN", "block") {
		t.Fatalf("expected structural blocks missing: %#v", response.Findings)
	}
}

func piLaunchHasFinding(response piLaunchPreflightResponse, code, severity string) bool {
	for _, finding := range response.Findings {
		if finding.Code == code && finding.Severity == severity {
			return true
		}
	}
	return false
}

func piLaunchTestPublicKey(fill byte) string {
	raw := make([]byte, 35)
	raw[0] = 6 << 3
	for index := 1; index < 33; index++ {
		raw[index] = fill
	}
	checksum := crc16XModem(raw[:33])
	raw[33] = byte(checksum)
	raw[34] = byte(checksum >> 8)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
}
