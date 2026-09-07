package handlers

import "strings"

// firstNonEmpty returns the first non-blank value after trimming whitespace.
// It is a generic handler-package primitive used by live evidence, account and
// owner flows; it must not be coupled to any retired product module.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
