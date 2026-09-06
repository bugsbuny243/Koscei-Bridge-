package handlers

import (
	"reflect"
	"testing"
)

func TestNeonAuthConfigMissingByDefault(t *testing.T) {
	t.Setenv("NEON_AUTH_BASE_URL", "")
	t.Setenv("EXPO_PUBLIC_NEON_AUTH_URL", "")
	t.Setenv("NEON_AUTH_ISSUER", "")
	t.Setenv("NEON_AUTH_JWKS_URL", "")
	t.Setenv("NEON_AUTH_STATE_SECRET", "")
	t.Setenv("KOSCHEI_AUTH_STATE_SECRET", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("CORS_ORIGIN", "")
	t.Setenv("CORS_ALLOWED_ORIGIN", "")

	if got := configuredNeonAuthBaseURL(); got != "" {
		t.Fatalf("configuredNeonAuthBaseURL() = %q, want empty", got)
	}
	if got := configuredPublicNeonAuthURL(); got != "" {
		t.Fatalf("configuredPublicNeonAuthURL() = %q, want empty", got)
	}
	if got := configuredNeonAuthIssuer(); got != "" {
		t.Fatalf("configuredNeonAuthIssuer() = %q, want empty", got)
	}
	if got := configuredNeonAuthJWKSURL(); got != "" {
		t.Fatalf("configuredNeonAuthJWKSURL() = %q, want empty", got)
	}
}

func TestConfiguredPublicNeonAuthURLPrefersExplicitPublicURL(t *testing.T) {
	t.Setenv("NEON_AUTH_BASE_URL", "https://private.example/neondb/auth")
	t.Setenv("EXPO_PUBLIC_NEON_AUTH_URL", "https://public.example/neondb/auth/")

	if got, want := configuredPublicNeonAuthURL(), "https://public.example/neondb/auth"; got != want {
		t.Fatalf("configuredPublicNeonAuthURL() = %q, want %q", got, want)
	}
}

func TestConfiguredNeonAuthIssuerFallsBackToBaseURL(t *testing.T) {
	t.Setenv("NEON_AUTH_BASE_URL", "https://auth.example/neondb/auth/")
	t.Setenv("NEON_AUTH_ISSUER", "")

	if got, want := configuredNeonAuthIssuer(), "https://auth.example/neondb/auth"; got != want {
		t.Fatalf("configuredNeonAuthIssuer() = %q, want %q", got, want)
	}
}

func TestConfiguredNeonAuthIssuerPreservesExplicitHostOnlyIssuer(t *testing.T) {
	t.Setenv("NEON_AUTH_BASE_URL", "https://auth.example/neondb/auth")
	t.Setenv("NEON_AUTH_ISSUER", "https://auth.example/")

	if got, want := configuredNeonAuthIssuer(), "https://auth.example"; got != want {
		t.Fatalf("configuredNeonAuthIssuer() = %q, want %q", got, want)
	}
}

func TestConfiguredNeonAuthIssuerPreservesExplicitDifferentIssuer(t *testing.T) {
	t.Setenv("NEON_AUTH_BASE_URL", "https://auth.example/neondb/auth")
	t.Setenv("NEON_AUTH_ISSUER", "https://issuer.example/custom")

	if got, want := configuredNeonAuthIssuer(), "https://issuer.example/custom"; got != want {
		t.Fatalf("configuredNeonAuthIssuer() = %q, want %q", got, want)
	}
}

func TestMissingProductionAuthEnv(t *testing.T) {
	t.Setenv("NEON_AUTH_BASE_URL", "")
	t.Setenv("NEON_AUTH_ISSUER", "issuer")
	t.Setenv("NEON_AUTH_JWKS_URL", "jwks")
	t.Setenv("NEON_AUTH_STATE_SECRET", "secret")
	t.Setenv("KOSCHEI_AUTH_STATE_SECRET", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("CORS_ORIGIN", "https://example.com")
	t.Setenv("CORS_ALLOWED_ORIGIN", "")

	if got, want := MissingProductionAuthEnv(), []string{"NEON_AUTH_BASE_URL"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("MissingProductionAuthEnv() = %#v, want %#v", got, want)
	}
}

func TestMissingProductionAuthEnvDoesNotRequireDedicatedStateSecret(t *testing.T) {
	t.Setenv("NEON_AUTH_BASE_URL", "https://auth.example")
	t.Setenv("NEON_AUTH_ISSUER", "issuer")
	t.Setenv("NEON_AUTH_JWKS_URL", "jwks")
	t.Setenv("NEON_AUTH_STATE_SECRET", "")
	t.Setenv("KOSCHEI_AUTH_STATE_SECRET", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("CORS_ORIGIN", "")
	t.Setenv("CORS_ALLOWED_ORIGIN", "https://example.com")

	if got := MissingProductionAuthEnv(); len(got) != 0 {
		t.Fatalf("MissingProductionAuthEnv() = %#v, want empty", got)
	}
}

func TestMissingProductionAuthEnvReportsAlternativeGroups(t *testing.T) {
	t.Setenv("NEON_AUTH_BASE_URL", "https://auth.example")
	t.Setenv("NEON_AUTH_ISSUER", "issuer")
	t.Setenv("NEON_AUTH_JWKS_URL", "jwks")
	t.Setenv("NEON_AUTH_STATE_SECRET", "")
	t.Setenv("KOSCHEI_AUTH_STATE_SECRET", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("CORS_ORIGIN", "")
	t.Setenv("CORS_ALLOWED_ORIGIN", "")

	want := []string{"CORS_ORIGIN or CORS_ALLOWED_ORIGIN"}
	if got := MissingProductionAuthEnv(); !reflect.DeepEqual(got, want) {
		t.Fatalf("MissingProductionAuthEnv() = %#v, want %#v", got, want)
	}
}
