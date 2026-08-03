package handlers

import "encoding/json"

// MarshalJSON makes the canonical public token-scan endpoint publish the same
// versioned customer-response contract enforced by the production acceptance
// probe. The alias avoids recursive marshaling and preserves every legacy field.
func (response tokenScanResponse) MarshalJSON() ([]byte, error) {
	type tokenScanResponseAlias tokenScanResponse
	return json.Marshal(struct {
		ResponseSchemaVersion string `json:"response_schema_version"`
		tokenScanResponseAlias
	}{
		ResponseSchemaVersion: customerInvestigationResponseSchemaVersion,
		tokenScanResponseAlias: tokenScanResponseAlias(response),
	})
}
