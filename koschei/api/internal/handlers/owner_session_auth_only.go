package handlers

import (
	"os"
	"strings"
)

func ownerSessionMemoryAllowed() bool {
	if !isProduction() {
		return true
	}
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("KOSCHEI_NEON_AUTH_ONLY")))
	return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
}
