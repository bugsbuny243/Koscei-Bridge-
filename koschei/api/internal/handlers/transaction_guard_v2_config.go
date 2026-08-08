package handlers

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

const maxConfiguredGuardPrograms = 64

func (h *Handler) TransactionGuardV2Configured(w http.ResponseWriter, r *http.Request) {
	if err := validateRequiredTransactionGuardEnforcementConfig(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":      false,
			"code":    "transaction_guard_enforcement_configuration_invalid",
			"message": "Transaction Guard enforcement is required but its signing configuration is invalid.",
		})
		return
	}
	if err := validateGuardOperatorBlocklist(os.Getenv("TRANSACTION_GUARD_BLOCKED_PROGRAMS")); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":      false,
			"code":    "transaction_guard_configuration_invalid",
			"message": "Transaction Guard is unavailable because its operator program policy is invalid.",
		})
		return
	}
	h.TransactionGuardV2EvidenceFirst(w, r)
}

func validateGuardOperatorBlocklist(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	values := strings.Split(raw, ",")
	if len(values) > maxConfiguredGuardPrograms {
		return fmt.Errorf("operator blocklist exceeds %d programs", maxConfiguredGuardPrograms)
	}
	for index, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || !isValidSolanaAddress(value) {
			return fmt.Errorf("operator blocklist entry %d is not a valid Solana program address", index)
		}
	}
	return nil
}
