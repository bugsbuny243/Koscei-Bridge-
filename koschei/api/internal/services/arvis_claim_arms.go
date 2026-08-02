package services

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

type arvisClaimSurfaceEvidence struct {
	Available         bool
	Original          string
	Scheme            string
	Host              string
	Port              string
	Path              string
	HTTPS             bool
	SchemeMissing     bool
	HasUserInfo       bool
	IPLiteralHost     bool
	PunycodeHost      bool
	NonStandardPort   bool
	ExcessSubdomains  bool
	SecretTerms       []string
	SigningTerms      []string
	RedirectTerms     []string
	PromotionTerms    []string
	LongEncodedValues int
}

func EnrichArvisBundleWithClaimSurface(bundle SecurityRadarBundle) SecurityRadarBundle {
	arms := ArvisArmsFromBundle(bundle)
	if len(arms) == 0 {
		return bundle
	}
	if bundle.Metadata == nil {
		bundle.Metadata = map[string]any{}
	}
	if attempted, _ := bundle.Metadata["claim_surface_enrichment_attempted"].(bool); attempted {
		return bundle
	}
	bundle.Metadata["claim_surface_enrichment_attempted"] = true
	evidence := parseArvisClaimSurface(bundle.Target)
	if !evidence.Available {
		bundle.Metadata["claim_surface_evidence_available"] = false
		return bundle
	}

	req := SecurityRadarRequest{Target: bundle.Target, Network: bundle.Network, Mode: bundle.WatchMode}
	generatedAt := time.Now().UTC().Format(time.RFC3339)
	replaceArvisArm(arms, buildWalletlessClaimArm(req, evidence, generatedAt))
	replaceArvisArm(arms, buildClaimSurfaceArm(req, evidence, generatedAt))
	verified := verifiedArvisEvidenceCount(arms)
	bundle.Metadata["arvis_arms"] = arms
	bundle.Metadata["claim_surface_evidence_available"] = true
	bundle.Metadata["verified_arm_count"] = verified
	bundle.Metadata["runtime_arm_count"] = verified
	bundle.Metadata["final_verdict_source"] = "EvaluateUnifiedRadarVerdict"
	bundle.CustomerRecommendation = "evaluate_unified_rules"
	bundle.CustomerSummary = fmt.Sprintf("ARVIS collected parsed claim evidence in %d of 14 evidence arms; no arm issued a grade.", verified)
	return bundle
}

func parseArvisClaimSurface(raw string) arvisClaimSurfaceEvidence {
	raw = strings.TrimSpace(raw)
	out := arvisClaimSurfaceEvidence{Original: raw}
	if raw == "" || strings.ContainsAny(raw, "\r\n\t ") {
		return out
	}
	candidate := raw
	lowerRaw := strings.ToLower(raw)
	if !strings.HasPrefix(lowerRaw, "http://") && !strings.HasPrefix(lowerRaw, "https://") {
		if !strings.Contains(raw, ".") {
			return out
		}
		candidate = "https://" + raw
		out.SchemeMissing = true
	}
	parsed, err := url.Parse(candidate)
	if err != nil || strings.TrimSpace(parsed.Hostname()) == "" {
		return out
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return out
	}
	out.Available = true
	out.Scheme = strings.ToLower(parsed.Scheme)
	out.Host = strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	out.Port = parsed.Port()
	out.Path = parsed.EscapedPath()
	out.HTTPS = out.Scheme == "https" && !out.SchemeMissing
	out.HasUserInfo = parsed.User != nil
	out.IPLiteralHost = net.ParseIP(strings.Trim(out.Host, "[]")) != nil
	out.PunycodeHost = strings.Contains(out.Host, "xn--")
	out.NonStandardPort = out.Port != "" && !((out.Scheme == "https" && out.Port == "443") || (out.Scheme == "http" && out.Port == "80"))
	out.ExcessSubdomains = len(strings.Split(out.Host, ".")) >= 5

	surface := strings.ToLower(parsed.Path + "?" + parsed.RawQuery + "#" + parsed.Fragment)
	out.SecretTerms = matchedClaimTerms(surface, []string{"seed", "seedphrase", "mnemonic", "privatekey", "private_key", "secretkey", "secret_key", "recoveryphrase", "recovery_phrase"})
	out.SigningTerms = matchedClaimTerms(surface, []string{"sign", "signature", "transaction", "approve", "authorize", "connectwallet", "connect_wallet", "walletconnect", "wallet_connect"})
	out.RedirectTerms = matchedClaimTerms(surface, []string{"redirect", "redirect_uri", "returnurl", "return_url", "callback", "continue", "next"})
	out.PromotionTerms = matchedClaimTerms(surface, []string{"claim", "airdrop", "reward", "bonus", "mint", "whitelist", "presale", "verify"})
	for key, values := range parsed.Query() {
		keyLower := strings.ToLower(strings.TrimSpace(key))
		if len(matchedClaimTerms(keyLower, []string{"seed", "mnemonic", "private", "secret", "recovery"})) > 0 {
			out.SecretTerms = appendUniqueStrings(out.SecretTerms, keyLower)
		}
		for _, value := range values {
			value = strings.TrimSpace(value)
			if len(value) >= 96 && looksEncodedClaimValue(value) {
				out.LongEncodedValues++
			}
		}
	}
	return out
}

func buildWalletlessClaimArm(req SecurityRadarRequest, e arvisClaimSurfaceEvidence, generatedAt string) SecurityRadarVerdict {
	if !e.Available {
		return unavailableArm("Walletless Claim Shield", ModuleWalletlessClaimShield, req, generatedAt, "A valid HTTP or HTTPS claim surface is required.")
	}
	signals := claimEvidenceSignals(e, ModuleWalletlessClaimShield)
	signals["secret_request_terms"] = e.SecretTerms
	signals["signing_request_terms"] = e.SigningTerms
	signals["long_encoded_value_count"] = e.LongEncodedValues
	signals["walletless_scope"] = "parsed URL structure only; no wallet connection or remote page execution"
	evidence := []string{
		fmt.Sprintf("Parsed claim surface host: %s; explicit HTTPS: %t.", e.Host, e.HTTPS),
		fmt.Sprintf("Secret/recovery terms: %d; signing/approval terms: %d.", len(e.SecretTerms), len(e.SigningTerms)),
		fmt.Sprintf("Long encoded query values: %d; URL user-info present: %t.", e.LongEncodedValues, e.HasUserInfo),
		"ARVIS did not connect a wallet, execute scripts, or submit a transaction while evaluating this surface.",
	}
	arm := verifiedEvidenceArm("Walletless Claim Shield", ModuleWalletlessClaimShield, req, 0, signals, evidence, generatedAt)
	arm.Verdict = "Claim instruction and wallet-request indicators were recorded; this arm does not issue a grade."
	return arm
}

func buildClaimSurfaceArm(req SecurityRadarRequest, e arvisClaimSurfaceEvidence, generatedAt string) SecurityRadarVerdict {
	if !e.Available {
		return unavailableArm("Claim Surface Risk", ModuleClaimSurfaceRisk, req, generatedAt, "A valid HTTP or HTTPS surface is required.")
	}
	signals := claimEvidenceSignals(e, ModuleClaimSurfaceRisk)
	signals["redirect_terms"] = e.RedirectTerms
	signals["promotion_terms"] = e.PromotionTerms
	signals["ip_literal_host"] = e.IPLiteralHost
	signals["punycode_host"] = e.PunycodeHost
	signals["non_standard_port"] = e.NonStandardPort
	signals["excess_subdomains"] = e.ExcessSubdomains
	evidence := []string{
		fmt.Sprintf("URL host=%s scheme=%s explicit_https=%t.", e.Host, e.Scheme, e.HTTPS),
		fmt.Sprintf("IP-literal=%t; punycode=%t; non-standard port=%t; excessive subdomains=%t.", e.IPLiteralHost, e.PunycodeHost, e.NonStandardPort, e.ExcessSubdomains),
		fmt.Sprintf("Redirect terms=%d; promotion/claim terms=%d.", len(e.RedirectTerms), len(e.PromotionTerms)),
		"These are structural observations, not a claim that the domain is confirmed malicious.",
	}
	arm := verifiedEvidenceArm("Claim Surface Risk", ModuleClaimSurfaceRisk, req, 0, signals, evidence, generatedAt)
	arm.Verdict = "Off-chain claim-surface indicators were recorded; this arm does not issue a grade."
	return arm
}

func claimEvidenceSignals(e arvisClaimSurfaceEvidence, moduleID string) map[string]any {
	return map[string]any{
		"module_id":                  moduleID,
		"verified_evidence":          true,
		"real_onchain_evidence":      false,
		"real_offchain_evidence":     true,
		"arm_evidence_available":     true,
		"evidence_status":            "verified_parsed_url",
		"data_quality":               "parsed_url_evidence",
		"url_host":                   e.Host,
		"url_scheme":                 e.Scheme,
		"explicit_https":             e.HTTPS,
		"scheme_missing":             e.SchemeMissing,
		"url_userinfo_present":       e.HasUserInfo,
		"remote_content_fetched":     false,
		"wallet_connection_executed": false,
		"numeric_score_disabled":     true,
		"grade_effect":               "none_at_arm_layer",
	}
}

func verifiedEvidenceArm(module, moduleID string, req SecurityRadarRequest, risk int, signals map[string]any, evidence []string, generatedAt string) SecurityRadarVerdict {
	return evidenceArm(module, moduleID, req, risk, signals, evidence, generatedAt)
}

// Compatibility adapter only. It cannot rank or select an arm.
func buildVerifiedFinalArm(req SecurityRadarRequest, _ []SecurityRadarVerdict, generatedAt string) SecurityRadarVerdict {
	return buildFinalArm(req, nil, generatedAt)
}

func matchedClaimTerms(surface string, terms []string) []string {
	surface = strings.ToLower(surface)
	out := []string{}
	for _, term := range terms {
		if strings.Contains(surface, strings.ToLower(term)) {
			out = appendUniqueStrings(out, term)
		}
	}
	return out
}

func appendUniqueStrings(values []string, candidates ...string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range candidates {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			values = append(values, value)
			seen[value] = true
		}
	}
	return values
}

func looksEncodedClaimValue(value string) bool {
	if len(value) < 96 {
		return false
	}
	allowed := 0
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("+/=_-", char) {
			allowed++
		}
	}
	return float64(allowed)/float64(len(value)) >= 0.92
}
