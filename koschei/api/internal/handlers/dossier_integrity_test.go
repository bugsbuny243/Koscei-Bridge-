package handlers

import (
	"encoding/json"
	"testing"
	"time"
)

func integrityFixture(t *testing.T) (dossierBundle, []byte) {
	t.Helper()
	body := dossierBody{
		DossierVersion:     dossierVersion,
		CaseRef:            "KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ProducedAt:         time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC),
		SourceSnapshotHash: "sha256:source",
		Target:             map[string]any{"kind": "token_mint", "id": "mint-1", "network": "solana-mainnet"},
		Verdict:            map[string]any{"grade": "B", "status": "review"},
		VerdictCard:        map[string]any{"signal_rows": []any{}},
		TechnicalReport: map[string]any{
			"final_verdict": map[string]any{"grade": "B"},
			"raw_amount":    json.Number("18446744073709551615"),
		},
		Verification: map[string]any{"hash_algorithm": "SHA-256"},
		Limitations:  []string{"test boundary"},
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal dossier body: %v", err)
	}
	bundle := dossierBundle{dossierBody: body, BundleHash: dossierSHA256(bodyBytes)}
	canonical, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal dossier bundle: %v", err)
	}
	return bundle, canonical
}

func TestVerifyStoredDossierBundleAcceptsExactCanonicalBundle(t *testing.T) {
	bundle, canonical := integrityFixture(t)
	verified, err := verifyStoredDossierBundle(canonical, bundle.CaseRef, bundle.BundleHash)
	if err != nil {
		t.Fatalf("verify exact canonical bundle: %v", err)
	}
	if verified.BundleHash != bundle.BundleHash || verified.CaseRef != bundle.CaseRef {
		t.Fatalf("verified bundle identity changed: %#v", verified)
	}
}

func TestVerifyStoredDossierBundleRejectsMissingStoredHash(t *testing.T) {
	bundle, canonical := integrityFixture(t)
	if _, err := verifyStoredDossierBundle(canonical, bundle.CaseRef, ""); err == nil {
		t.Fatal("missing database bundle_hash was accepted")
	}
}

func TestVerifyStoredDossierBundleRejectsMutatedBody(t *testing.T) {
	bundle, _ := integrityFixture(t)
	bundle.TechnicalReport = map[string]any{"mutated": true}
	canonical, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal mutated bundle: %v", err)
	}
	if _, err := verifyStoredDossierBundle(canonical, bundle.CaseRef, bundle.BundleHash); err == nil {
		t.Fatal("mutated dossier body was accepted with stale bundle hash")
	}
}

func TestVerifyStoredDossierBundleRejectsStoredHashMismatch(t *testing.T) {
	bundle, canonical := integrityFixture(t)
	if _, err := verifyStoredDossierBundle(canonical, bundle.CaseRef, "sha256:wrong"); err == nil {
		t.Fatal("database bundle_hash mismatch was accepted")
	}
}

func TestVerifyStoredDossierBundleRejectsCaseRefMismatch(t *testing.T) {
	bundle, canonical := integrityFixture(t)
	if _, err := verifyStoredDossierBundle(canonical, "KD1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", bundle.BundleHash); err == nil {
		t.Fatal("case_ref mismatch was accepted")
	}
}

func TestVerifyStoredDossierBundleRejectsNonCanonicalBytes(t *testing.T) {
	bundle, canonical := integrityFixture(t)
	canonical = append([]byte(" "), canonical...)
	if _, err := verifyStoredDossierBundle(canonical, bundle.CaseRef, bundle.BundleHash); err == nil {
		t.Fatal("non-canonical whitespace mutation was accepted")
	}
}
