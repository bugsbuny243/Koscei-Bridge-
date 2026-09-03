package handlers

import (
	"os"
	"strings"
)

func neonAuthOnlyMode() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("KOSCHEI_NEON_AUTH_ONLY")))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}
