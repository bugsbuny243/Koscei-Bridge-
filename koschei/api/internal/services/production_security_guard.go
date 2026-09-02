package services

import (
	"os"
	"strings"
)

func NeonAuthOnlyMode() bool {
	value := strings.TrimSpace(os.Getenv("KOSCHEI_NEON_AUTH_ONLY"))
	return strings.EqualFold(value, "1") || strings.EqualFold(value, "true") || strings.EqualFold(value, "yes") || strings.EqualFold(value, "on")
}

func MissingProductionSecurityEnv() []string {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production") {
		return nil
	}
	required := []string{"API_KEY_PEPPER", "USER_SESSION_SECRET", "OWNER_SECRET", "NEON_AUTH_JWKS_URL"}
	if !NeonAuthOnlyMode() {
		required = append(required, "DATABASE_URL")
	}
	missing := []string{}
	for _, key := range required {
		if strings.TrimSpace(os.Getenv(key)) == "" {
			missing = append(missing, key)
		}
	}
	return missing
}
