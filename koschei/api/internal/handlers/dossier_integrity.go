package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// verifyStoredDossierBundle proves that a stored canonical dossier still matches
// the exact byte-level representation produced by assembleDossierBundle and
// that both embedded and database hashes commit to the dossier body.
func verifyStoredDossierBundle(canonical []byte, caseRef, storedHash string) (dossierBundle, error) {
	canonical = bytes.TrimSpace(canonical)
	caseRef = strings.TrimSpace(caseRef)
	storedHash = strings.TrimSpace(storedHash)
	if len(canonical) == 0 || caseRef == "" {
		return dossierBundle{}, fmt.Errorf("dossier integrity input is incomplete")
	}

	var bundle dossierBundle
	if err := json.Unmarshal(canonical, &bundle); err != nil {
		return dossierBundle{}, fmt.Errorf("dossier canonical JSON is invalid: %w", err)
	}
	if bundle.CaseRef != caseRef {
		return dossierBundle{}, fmt.Errorf("dossier case_ref mismatch")
	}
	bundleHash := strings.TrimSpace(bundle.BundleHash)
	if bundleHash == "" {
		return dossierBundle{}, fmt.Errorf("dossier bundle_hash is missing")
	}

	// canonical_bundle is intentionally stored as the exact json.Marshal output.
	// Re-marshalling catches unknown top-level fields, alternate encodings and any
	// mutation that is not the canonical dossier representation.
	reencoded, err := json.Marshal(bundle)
	if err != nil {
		return dossierBundle{}, fmt.Errorf("dossier canonical JSON could not be re-encoded: %w", err)
	}
	if !bytes.Equal(canonical, reencoded) {
		return dossierBundle{}, fmt.Errorf("dossier canonical bytes are not canonical")
	}

	bodyBytes, err := json.Marshal(bundle.dossierBody)
	if err != nil {
		return dossierBundle{}, fmt.Errorf("dossier body could not be encoded: %w", err)
	}
	computed := dossierSHA256(bodyBytes)
	if bundleHash != computed {
		return dossierBundle{}, fmt.Errorf("dossier embedded bundle_hash mismatch")
	}
	if storedHash != "" && storedHash != computed {
		return dossierBundle{}, fmt.Errorf("dossier stored bundle_hash mismatch")
	}
	return bundle, nil
}
