package handlers

import (
	"net/http"
	"net/url"
	"os"
	"strings"
)

const defaultPublicAppURL = "https://tradepigloball.co"

var requiredProductionAuthEnv = [][]string{
	{"NEON_AUTH_BASE_URL"},
	{"NEON_AUTH_JWKS_URL"},
	{"CORS_ORIGIN", "CORS_ALLOWED_ORIGIN"},
}

func configuredNeonAuthBaseURL() string {
	return trimmedEnv("NEON_AUTH_BASE_URL")
}

func configuredPublicNeonAuthURL() string {
	if value := trimmedEnv("EXPO_PUBLIC_NEON_AUTH_URL"); value != "" {
		return strings.TrimRight(value, "/")
	}
	return strings.TrimRight(configuredNeonAuthBaseURL(), "/")
}

func configuredPublicAppURL() string {
	for _, name := range []string{"PUBLIC_APP_URL", "APP_BASE_URL", "SITE_URL", "CORS_ORIGIN", "CORS_ALLOWED_ORIGIN"} {
		if value := normalizeAbsoluteBaseURL(trimmedEnv(name)); value != "" {
			return value
		}
	}
	if isProduction() {
		return defaultPublicAppURL
	}
	return ""
}

func publicBaseURL(r *http.Request) string {
	if value := configuredPublicAppURL(); value != "" {
		return value
	}
	if r == nil {
		return ""
	}
	host := getHost(r)
	if host == "" {
		return ""
	}
	return strings.TrimRight(getScheme(r)+"://"+host, "/")
}

func absolutePublicURL(r *http.Request, path string) string {
	baseURL := publicBaseURL(r)
	if baseURL == "" {
		return ""
	}
	if parsed, err := url.Parse(strings.TrimSpace(path)); err == nil && parsed.IsAbs() {
		return strings.TrimRight(parsed.String(), "/")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return baseURL + path
}

func normalizeAbsoluteBaseURL(raw string) string {
	value := strings.TrimRight(strings.TrimSpace(raw), "/")
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ""
	}
	return value
}

func configuredNeonAuthIssuer() string {
	base := strings.TrimRight(configuredNeonAuthBaseURL(), "/")
	explicit := strings.TrimRight(trimmedEnv("NEON_AUTH_ISSUER"), "/")
	if explicit == "" {
		return base
	}

	// Legacy deployments stored only the Neon Auth origin in NEON_AUTH_ISSUER
	// while NEON_AUTH_BASE_URL carried the canonical /neondb/auth path. Normalize
	// that legacy form only when both values resolve to the same origin. A
	// different explicit issuer remains an exact trust boundary and is never
	// rewritten.
	if base != "" {
		explicitURL, explicitErr := url.Parse(explicit)
		baseURL, baseErr := url.Parse(base)
		if explicitErr == nil && baseErr == nil && explicitURL.IsAbs() && baseURL.IsAbs() &&
			strings.EqualFold(explicitURL.Scheme, baseURL.Scheme) &&
			strings.EqualFold(explicitURL.Host, baseURL.Host) &&
			(explicitURL.Path == "" || explicitURL.Path == "/") &&
			baseURL.Path != "" && baseURL.Path != "/" {
			return base
		}
	}
	return explicit
}

func configuredNeonAuthJWKSURL() string {
	return trimmedEnv("NEON_AUTH_JWKS_URL")
}

func trimmedEnv(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}

func MissingProductionAuthEnv() []string {
	missing := []string{}
	for _, alternatives := range requiredProductionAuthEnv {
		found := false
		for _, name := range alternatives {
			if trimmedEnv(name) != "" {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, strings.Join(alternatives, " or "))
		}
	}
	return missing
}

func ConfiguredNeonAuthJWKSURL() string {
	return configuredNeonAuthJWKSURL()
}

func ConfiguredPublicNeonAuthURL() string {
	return configuredPublicNeonAuthURL()
}

func ConfiguredNeonAuthIssuer() string {
	return configuredNeonAuthIssuer()
}
