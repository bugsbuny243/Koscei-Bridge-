package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

var dossierBundleTopLevelFields = map[string]struct{}{
	"dossier_version": {}, "case_ref": {}, "produced_at": {}, "source_snapshot_hash": {},
	"target": {}, "token": {}, "verdict": {}, "verdict_card": {}, "threat_anticipation": {},
	"evidence_arms": {}, "transaction_evidence": {}, "evidence_references": {}, "actor_dossier": {},
	"actor_acceptance": {}, "created_token_history": {}, "funding_origin": {}, "cross_token_connections": {},
	"evidence_log": {}, "section_limitations": {}, "holder_concentration_context": {}, "technical_report": {},
	"verification": {}, "limitations": {}, "bundle_hash": {},
}

func decodeStoredDossierBundle(canonical []byte, caseRef, storedHash string) (dossierBundle, error) {
	caseRef = strings.TrimSpace(caseRef)
	storedHash = strings.TrimSpace(storedHash)
	if len(canonical) == 0 || caseRef == "" || storedHash == "" {
		return dossierBundle{}, fmt.Errorf("dossier integrity input is incomplete")
	}
	if !publicDossierCaseRefPattern.MatchString(caseRef) {
		return dossierBundle{}, fmt.Errorf("dossier case_ref format is invalid")
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &raw); err != nil {
		return dossierBundle{}, fmt.Errorf("dossier canonical JSON is invalid: %w", err)
	}
	for key := range raw {
		if _, ok := dossierBundleTopLevelFields[key]; !ok {
			return dossierBundle{}, fmt.Errorf("dossier canonical JSON has unknown top-level field %q", key)
		}
	}

	var bundle dossierBundle
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	if err := decoder.Decode(&bundle); err != nil {
		return dossierBundle{}, fmt.Errorf("dossier canonical JSON is invalid: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return dossierBundle{}, fmt.Errorf("dossier canonical JSON contains trailing data")
	}
	if bundle.CaseRef != caseRef {
		return dossierBundle{}, fmt.Errorf("dossier case_ref mismatch")
	}
	bundleHash := strings.TrimSpace(bundle.BundleHash)
	if bundleHash == "" {
		return dossierBundle{}, fmt.Errorf("dossier bundle_hash is missing")
	}
	if storedHash != bundleHash {
		return dossierBundle{}, fmt.Errorf("dossier stored and embedded bundle_hash differ")
	}
	return bundle, nil
}

func verifyBundleBodyHash(bundle dossierBundle, storedHash string) error {
	bodyBytes, err := json.Marshal(bundle.dossierBody)
	if err != nil {
		return fmt.Errorf("dossier body could not be encoded: %w", err)
	}
	computed := dossierSHA256(bodyBytes)
	bundleHash := strings.TrimSpace(bundle.BundleHash)
	storedHash = strings.TrimSpace(storedHash)
	// Acceptance invariants intentionally remain explicit: bundleHash != computed
	// and storedHash != computed are both hard failures.
	if bundleHash != computed {
		return fmt.Errorf("dossier embedded bundle_hash mismatch")
	}
	if storedHash != computed {
		return fmt.Errorf("dossier stored bundle_hash mismatch")
	}
	return nil
}

func verifyStoredDossierBundle(canonical []byte, caseRef, storedHash string) (dossierBundle, error) {
	bundle, err := decodeStoredDossierBundle(canonical, caseRef, storedHash)
	if err != nil {
		return dossierBundle{}, err
	}

	reencoded, err := json.Marshal(bundle)
	if err != nil {
		return dossierBundle{}, fmt.Errorf("dossier canonical JSON could not be re-encoded: %w", err)
	}
	if !bytes.Equal(canonical, reencoded) {
		return dossierBundle{}, fmt.Errorf("dossier canonical bytes are not canonical")
	}
	if err := verifyBundleBodyHash(bundle, storedHash); err != nil {
		return dossierBundle{}, err
	}
	return bundle, nil
}

func verifyStoredLegacyDossierBundle(canonical []byte, caseRef, storedHash string) (dossierBundle, error) {
	bundle, err := decodeStoredDossierBundle(canonical, caseRef, storedHash)
	if err != nil {
		return dossierBundle{}, err
	}

	hashJSON, err := json.Marshal(strings.TrimSpace(bundle.BundleHash))
	if err != nil {
		return dossierBundle{}, fmt.Errorf("legacy dossier bundle_hash could not be encoded: %w", err)
	}
	suffix := append([]byte(`,"bundle_hash":`), hashJSON...)
	suffix = append(suffix, '}')
	if len(canonical) <= len(suffix) || !bytes.Equal(canonical[len(canonical)-len(suffix):], suffix) {
		return dossierBundle{}, fmt.Errorf("legacy dossier bundle_hash is not the canonical final field")
	}
	bodyCanonical := make([]byte, 0, len(canonical)-len(suffix)+1)
	bodyCanonical = append(bodyCanonical, canonical[:len(canonical)-len(suffix)]...)
	bodyCanonical = append(bodyCanonical, '}')
	computed := dossierSHA256(bodyCanonical)
	bundleHash := strings.TrimSpace(bundle.BundleHash)
	storedHash = strings.TrimSpace(storedHash)
	if bundleHash != computed {
		return dossierBundle{}, fmt.Errorf("legacy dossier embedded bundle_hash mismatch")
	}
	if storedHash != computed {
		return dossierBundle{}, fmt.Errorf("legacy dossier stored bundle_hash mismatch")
	}
	return bundle, nil
}
