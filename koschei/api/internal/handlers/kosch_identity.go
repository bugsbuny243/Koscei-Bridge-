package handlers

import (
	"os"
	"strings"
)

// configuredKoscheiTokenMint identifies the KOSCH ecosystem asset for display
// and telemetry only. Token holdings never grant SaaS access or evidence/verdict
// authority.
func configuredKoscheiTokenMint() string {
	return strings.TrimSpace(firstNonEmptyString(os.Getenv("KOSCHEI_TOKEN_MINT"), os.Getenv("KOSCH_TOKEN_MINT"), officialKOSCHMint))
}
