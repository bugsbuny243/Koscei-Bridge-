package handlers

import (
	"net/http"
	"strings"
)

// PublicTransactionSimulate exposes the existing read-only transaction
// firewall to retail users without login or wallet connection. It never signs,
// submits or blocks a transaction; it only simulates and explains it.
func (h *Handler) PublicTransactionSimulate(w http.ResponseWriter, r *http.Request) {
	var input shieldPreflightRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "code": "invalid_request", "message": "Geçersiz istek gövdesi."})
		return
	}
	if strings.TrimSpace(input.Transaction) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "code": "transaction_required", "message": "Base64 serialized transaction gereklidir."})
		return
	}
	h.transactionFirewallSimulate(w, r, input)
}
