package services

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	piTOMLWellKnownPath    = "/.well-known/pi.toml"
	piTOMLRequestTimeout   = 5 * time.Second
	piTOMLMaxResponseBytes = 256 << 10
	piTOMLEvidenceSource   = "pi_home_domain_toml"
)

type PiDomainBindingObservation struct {
	Status                string   `json:"status"`
	VerificationStatus    string   `json:"verification_status"`
	Source                string   `json:"source"`
	Domain                string   `json:"domain,omitempty"`
	URL                   string   `json:"url,omitempty"`
	AssetCode             string   `json:"asset_code,omitempty"`
	Issuer                string   `json:"issuer,omitempty"`
	Name                  string   `json:"name,omitempty"`
	Description           string   `json:"description,omitempty"`
	Image                 string   `json:"image,omitempty"`
	HTTPStatus            int      `json:"http_status,omitempty"`
	ContentType           string   `json:"content_type,omitempty"`
	ExactAssetMatch       bool     `json:"exact_asset_match"`
	RequiredFieldsPresent bool     `json:"required_fields_present"`
	IdentityClaim         bool     `json:"identity_claim"`
	FetchedAt             string   `json:"fetched_at,omitempty"`
	Limitations           []string `json:"limitations,omitempty"`
}

type piTOMLCurrency struct {
	Code   string
	Issuer string
	Name   string
	Desc   string
	Image  string
}

// enrichPiDomainBindingEvidence verifies the issuer's home_domain against the
// exact CODE:ISSUER entry in /.well-known/pi.toml. The observation is a domain
// to asset provenance relation only; it must never become a real-world identity
// or ownership claim.
func enrichPiDomainBindingEvidence(ctx context.Context, analysis ArvisAnalysis, target PiRadarTarget) ArvisAnalysis {
	if target.Kind != piRadarTargetKindAsset {
		return analysis
	}
	homeDomain := piHomeDomainFromAnalysis(analysis)
	observation := collectPiDomainBindingObservation(ctx, target, homeDomain)
	if analysis.Bundle.Metadata == nil {
		analysis.Bundle.Metadata = map[string]any{}
	}
	analysis.Bundle.Metadata["pi_domain_binding"] = observation
	analysis.Bundle.Metadata["pi_domain_binding_source"] = piTOMLEvidenceSource
	analysis.Bundle.Metadata["pi_domain_binding_identity_claim"] = false

	for index := range analysis.Arms {
		switch analysis.Arms[index].ModuleID {
		case ModuleCreatorLinkAnalysis, ModuleClaimSurfaceRisk:
			analysis.Arms[index] = applyPiDomainObservationToArm(analysis.Arms[index], observation)
		}
	}
	analysis.Graph = applyPiDomainObservationToGraph(analysis.Graph, target, observation)
	analysis.Bundle.Metadata["arvis_arms"] = analysis.Arms
	analysis.Bundle.Metadata["intelligence_graph"] = analysis.Graph
	return analysis
}

func piHomeDomainFromAnalysis(analysis ArvisAnalysis) string {
	for _, arm := range analysis.Arms {
		if arm.ModuleID != ModuleCreatorLinkAnalysis && arm.ModuleID != ModuleClaimSurfaceRisk {
			continue
		}
		if arm.Signals == nil {
			continue
		}
		value := strings.TrimSpace(fmt.Sprint(arm.Signals["home_domain"]))
		if value != "" && value != "<nil>" {
			return value
		}
	}
	return ""
}

func collectPiDomainBindingObservation(ctx context.Context, target PiRadarTarget, homeDomain string) PiDomainBindingObservation {
	out := PiDomainBindingObservation{
		Status:             "not_configured",
		VerificationStatus: "not_verified",
		Source:             piTOMLEvidenceSource,
		AssetCode:          target.AssetCode,
		Issuer:             target.Issuer,
		IdentityClaim:      false,
		Limitations:        []string{},
	}
	domain, err := normalizePiHomeDomain(homeDomain)
	if err != nil {
		if strings.TrimSpace(homeDomain) == "" {
			out.Limitations = append(out.Limitations, "Issuer account does not expose a home_domain; no pi.toml provenance fetch was attempted.")
			return out
		}
		out.Status = "invalid_home_domain"
		out.Limitations = append(out.Limitations, "Issuer home_domain was rejected by the public-domain safety policy: "+compactPiHorizonError(err))
		return out
	}
	out.Domain = domain
	out.URL = "https://" + domain + piTOMLWellKnownPath

	client := newPiProvenanceHTTPClient()
	requestCtx, cancel := context.WithTimeout(ctx, piTOMLRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, out.URL, nil)
	if err != nil {
		out.Status = "fetch_failed"
		out.Limitations = append(out.Limitations, "pi.toml request could not be created.")
		return out
	}
	req.Header.Set("Accept", "text/plain")
	res, err := client.Do(req)
	if err != nil {
		out.Status = "fetch_failed"
		out.Limitations = append(out.Limitations, "pi.toml HTTPS fetch failed: "+compactPiHorizonError(err))
		return out
	}
	defer res.Body.Close()
	out.HTTPStatus = res.StatusCode
	out.ContentType = strings.TrimSpace(res.Header.Get("Content-Type"))
	out.FetchedAt = time.Now().UTC().Format(time.RFC3339)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		out.Status = "fetch_failed"
		out.Limitations = append(out.Limitations, fmt.Sprintf("pi.toml returned HTTP %d.", res.StatusCode))
		return out
	}
	if !strings.HasPrefix(strings.ToLower(out.ContentType), "text/plain") {
		out.Status = "content_type_mismatch"
		out.Limitations = append(out.Limitations, "Official Pi token guidance requires pi.toml to be served as text/plain; binding was not verified.")
		return out
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, piTOMLMaxResponseBytes+1))
	if err != nil {
		out.Status = "fetch_failed"
		out.Limitations = append(out.Limitations, "pi.toml response body could not be read.")
		return out
	}
	if len(body) > piTOMLMaxResponseBytes {
		out.Status = "response_too_large"
		out.Limitations = append(out.Limitations, "pi.toml exceeded the bounded provenance response size.")
		return out
	}
	currencies, err := parsePiTOMLCurrencies(body)
	if err != nil {
		out.Status = "parse_failed"
		out.Limitations = append(out.Limitations, "pi.toml could not be parsed by the bounded CURRENCIES parser: "+compactPiHorizonError(err))
		return out
	}
	for _, currency := range currencies {
		if currency.Code != target.AssetCode || currency.Issuer != target.Issuer {
			continue
		}
		out.ExactAssetMatch = true
		out.Name = currency.Name
		out.Description = currency.Desc
		out.Image = currency.Image
		out.RequiredFieldsPresent = currency.Code != "" && currency.Issuer != "" && currency.Name != "" && currency.Desc != "" && currency.Image != ""
		if !out.RequiredFieldsPresent {
			out.Status = "incomplete_asset_entry"
			out.Limitations = append(out.Limitations, "Exact CODE:ISSUER entry exists but one or more required Pi token metadata fields are missing.")
			return out
		}
		out.Status = "verified_asset_domain_binding"
		out.VerificationStatus = "verified"
		out.Limitations = append(out.Limitations, "Verified relation is limited to the on-chain issuer home_domain and exact pi.toml asset entry; it is not proof of legal or real-world identity.")
		return out
	}
	out.Status = "asset_not_declared"
	out.Limitations = append(out.Limitations, "Fetched pi.toml did not contain an exact CODE:ISSUER CURRENCIES entry for the scanned asset.")
	return out
}

func applyPiDomainObservationToArm(arm SecurityRadarVerdict, observation PiDomainBindingObservation) SecurityRadarVerdict {
	if arm.Signals == nil {
		arm.Signals = map[string]any{}
	}
	arm.Signals["pi_domain_binding"] = observation
	arm.Signals["domain_verified"] = observation.VerificationStatus == "verified"
	arm.Signals["domain_binding_status"] = observation.Status
	arm.Signals["domain_binding_source"] = observation.Source
	arm.Signals["identity_claim"] = false

	switch observation.Status {
	case "verified_asset_domain_binding":
		arm.Evidence = append(arm.Evidence,
			fmt.Sprintf("Verified Pi asset-domain binding: %s declares exact asset %s:%s in %s.", observation.Domain, observation.AssetCode, observation.Issuer, observation.URL),
			"The verified domain relation is protocol provenance only and does not identify a real-world controller.",
		)
	case "not_configured":
		arm.Evidence = append(arm.Evidence, "No issuer home_domain was available, so ARVIS did not claim domain provenance.")
	default:
		arm.Evidence = append(arm.Evidence, "Pi domain provenance status: "+observation.Status+". No verified domain binding was claimed.")
	}
	return arm
}

func applyPiDomainObservationToGraph(graph SecurityRadarVerdict, target PiRadarTarget, observation PiDomainBindingObservation) SecurityRadarVerdict {
	if observation.VerificationStatus != "verified" || graph.Signals == nil {
		return graph
	}
	nodes := piGraphMaps(graph.Signals["nodes"])
	edges := piGraphMaps(graph.Signals["edges"])
	nodes = append(nodes, map[string]any{"id": observation.Domain, "kind": "home_domain", "chain": "pi", "verification_status": "verified"})
	edges = append(edges, map[string]any{
		"source":              target.Issuer,
		"destination":         observation.Domain,
		"relation":            "home_domain_asset_binding",
		"asset":               target.AssetCode + ":" + target.Issuer,
		"source_url":          observation.URL,
		"verification_status": "verified",
	})
	graph.Signals["nodes"] = nodes
	graph.Signals["edges"] = edges
	graph.Signals["pi_domain_binding"] = observation
	graph.Evidence = append(graph.Evidence, "Verified home-domain relation was added from the exact pi.toml CODE:ISSUER match.")
	return graph
}

func piGraphMaps(raw any) []map[string]any {
	switch values := raw.(type) {
	case []map[string]any:
		return append([]map[string]any{}, values...)
	case []any:
		out := make([]map[string]any, 0, len(values))
		for _, item := range values {
			if value, ok := item.(map[string]any); ok {
				out = append(out, value)
			}
		}
		return out
	default:
		return []map[string]any{}
	}
}

func normalizePiHomeDomain(raw string) (string, error) {
	host := strings.TrimSpace(strings.ToLower(raw))
	if host == "" {
		return "", errors.New("home_domain is empty")
	}
	if len(host) > 253 || strings.ContainsAny(host, "/\\@?#") || strings.Contains(host, ":") {
		return "", errors.New("home_domain must be a bare DNS hostname without scheme, path, credentials or port")
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return "", errors.New("home_domain has an invalid leading or trailing dot")
	}
	if ip := net.ParseIP(host); ip != nil {
		return "", errors.New("IP-literal home_domain is not allowed")
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return "", errors.New("local home_domain is not allowed")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", errors.New("home_domain must contain a public DNS suffix")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("home_domain contains an invalid DNS label")
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return "", errors.New("home_domain contains non-ASCII or unsupported DNS characters")
		}
	}
	return host, nil
}

func newPiProvenanceHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: piTOMLRequestTimeout, KeepAlive: 15 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		IdleConnTimeout:       15 * time.Second,
		TLSHandshakeTimeout:   piTOMLRequestTimeout,
		ResponseHeaderTimeout: piTOMLRequestTimeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil || len(resolved) == 0 {
				return nil, errors.New("home_domain DNS resolution failed")
			}
			for _, item := range resolved {
				if !piPublicIPAddress(item.IP) {
					return nil, errors.New("home_domain resolved to a non-public IP address")
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(resolved[0].IP.String(), port))
		},
	}
	return &http.Client{
		Timeout:   piTOMLRequestTimeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func piPublicIPAddress(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	for _, blocked := range []string{"100.64.0.0/10", "198.18.0.0/15", "fc00::/7"} {
		_, network, _ := net.ParseCIDR(blocked)
		if network != nil && network.Contains(ip) {
			return false
		}
	}
	return true
}

func parsePiTOMLCurrencies(body []byte) ([]piTOMLCurrency, error) {
	if len(body) == 0 {
		return nil, errors.New("empty pi.toml")
	}
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	currencies := []piTOMLCurrency{}
	var current *piTOMLCurrency
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[[") && strings.HasSuffix(line, "]]") {
			if current != nil {
				currencies = append(currencies, *current)
				current = nil
			}
			section := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "[["), "]]"))
			if section == "CURRENCIES" {
				current = &piTOMLCurrency{}
			}
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		parsed, ok := piTOMLQuotedValue(strings.TrimSpace(value))
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "code":
			current.Code = parsed
		case "issuer":
			current.Issuer = parsed
		case "name":
			current.Name = parsed
		case "desc":
			current.Desc = parsed
		case "image":
			current.Image = parsed
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if current != nil {
		currencies = append(currencies, *current)
	}
	return currencies, nil
}

func piTOMLQuotedValue(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if raw[0] == '\'' {
		end := strings.Index(raw[1:], "'")
		if end < 0 {
			return "", false
		}
		end++
		value := raw[1:end]
		rest := strings.TrimSpace(raw[end+1:])
		if rest != "" && !strings.HasPrefix(rest, "#") {
			return "", false
		}
		return value, true
	}
	if raw[0] != '"' {
		return "", false
	}
	escaped := false
	for index := 1; index < len(raw); index++ {
		switch raw[index] {
		case '\\':
			escaped = !escaped
		case '"':
			if escaped {
				escaped = false
				continue
			}
			quoted := raw[:index+1]
			value, err := strconv.Unquote(quoted)
			if err != nil {
				return "", false
			}
			rest := strings.TrimSpace(raw[index+1:])
			if rest != "" && !strings.HasPrefix(rest, "#") {
				return "", false
			}
			return value, true
		default:
			escaped = false
		}
	}
	return "", false
}

func piTOMLURLForDomain(domain string) (*url.URL, error) {
	host, err := normalizePiHomeDomain(domain)
	if err != nil {
		return nil, err
	}
	return url.Parse("https://" + host + piTOMLWellKnownPath)
}
