package services

import (
	"net"
	"strings"
	"testing"
)

func TestNormalizePiHomeDomainAcceptsPublicDNSName(t *testing.T) {
	got, err := normalizePiHomeDomain("Token.Example.COM")
	if err != nil {
		t.Fatalf("normalize public domain: %v", err)
	}
	if got != "token.example.com" {
		t.Fatalf("normalized domain = %q", got)
	}
}

func TestNormalizePiHomeDomainRejectsSSRFAndURLShapes(t *testing.T) {
	for _, input := range []string{
		"localhost",
		"127.0.0.1",
		"10.0.0.1",
		"https://example.com",
		"example.com:443",
		"user@example.com",
		"example.com/path",
		"metadata.internal",
		"singlelabel",
	} {
		if got, err := normalizePiHomeDomain(input); err == nil {
			t.Fatalf("expected %q to be rejected, got %q", input, got)
		}
	}
}

func TestPiPublicIPAddressRejectsInternalRanges(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1",
		"10.0.0.1",
		"172.16.1.1",
		"192.168.1.1",
		"169.254.169.254",
		"100.64.0.1",
		"198.18.0.1",
		"::1",
		"fc00::1",
		"fe80::1",
	} {
		if piPublicIPAddress(net.ParseIP(raw)) {
			t.Fatalf("expected %s to be rejected", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !piPublicIPAddress(net.ParseIP(raw)) {
			t.Fatalf("expected %s to be accepted", raw)
		}
	}
}

func TestParsePiTOMLCurrenciesExactAssetAndRequiredFields(t *testing.T) {
	body := []byte(`VERSION="2.0"

[[CURRENCIES]]
code="OTHER"
issuer="GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
name="Other"
desc="Other asset"
image="https://example.com/other.png"

[[CURRENCIES]]
code="KOSCHEI"
issuer="GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBRAP"
name="Koschei"
desc="Security token metadata"
image="https://example.com/koschei.png" # exact image
`)
	currencies, err := parsePiTOMLCurrencies(body)
	if err != nil {
		t.Fatalf("parse pi.toml: %v", err)
	}
	if len(currencies) != 2 {
		t.Fatalf("currency count = %d", len(currencies))
	}
	got := currencies[1]
	if got.Code != "KOSCHEI" || got.Issuer != "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBRAP" {
		t.Fatalf("wrong exact asset: %#v", got)
	}
	if got.Name == "" || got.Desc == "" || got.Image == "" {
		t.Fatalf("required metadata missing: %#v", got)
	}
}

func TestParsePiTOMLCurrenciesSupportsLiteralStringsAndIgnoresOtherSections(t *testing.T) {
	body := []byte(`[[DOCUMENTATION]]
ORG_NAME="ignored"

[[CURRENCIES]]
code='ABC'
issuer='GISSUER'
name='Asset name'
desc='Asset description'
image='https://example.com/a.png'
`)
	currencies, err := parsePiTOMLCurrencies(body)
	if err != nil {
		t.Fatalf("parse pi.toml: %v", err)
	}
	if len(currencies) != 1 || currencies[0].Code != "ABC" || currencies[0].Name != "Asset name" {
		t.Fatalf("unexpected currencies: %#v", currencies)
	}
}

func TestPiTOMLQuotedValueRejectsTrailingExecutableGarbage(t *testing.T) {
	if value, ok := piTOMLQuotedValue(`"safe" unexpected`); ok {
		t.Fatalf("unexpected parse of trailing garbage: %q", value)
	}
	value, ok := piTOMLQuotedValue(`"safe" # comment`)
	if !ok || value != "safe" {
		t.Fatalf("commented value = %q ok=%t", value, ok)
	}
}

func TestApplyPiDomainObservationDoesNotCreateIdentityClaim(t *testing.T) {
	arm := SecurityRadarVerdict{ModuleID: ModuleCreatorLinkAnalysis, Signals: map[string]any{}}
	observation := PiDomainBindingObservation{
		Status:             "verified_asset_domain_binding",
		VerificationStatus: "verified",
		Source:             piTOMLEvidenceSource,
		Domain:             "example.com",
		URL:                "https://example.com/.well-known/pi.toml",
		AssetCode:          "ABC",
		Issuer:             "GISSUER",
	}
	got := applyPiDomainObservationToArm(arm, observation)
	if got.Signals["identity_claim"] != false {
		t.Fatalf("identity claim must stay false: %#v", got.Signals)
	}
	joined := strings.Join(got.Evidence, " ")
	if !strings.Contains(joined, "protocol provenance") {
		t.Fatalf("expected provenance limitation in evidence: %s", joined)
	}
}
