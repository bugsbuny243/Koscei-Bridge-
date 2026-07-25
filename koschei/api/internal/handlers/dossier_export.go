package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

func (h *Handler) DossierExport(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/dossier/"))
	if target == "" || strings.Contains(target, "/") {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "target is required")
		return
	}
	snapshot, err := h.loadDossierSnapshot(r.Context(), target, strings.TrimSpace(r.URL.Query().Get("verdict_id")))
	if err != nil {
		switch {
		case errors.Is(err, errDossierSourceIncomplete), errors.Is(err, context.Canceled):
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": "dossier_source_incomplete",
				"message": "An immutable signed investigation snapshot is required; export never rescans or refreshes missing evidence.",
			})
		case errors.Is(err, errDossierSourceHash):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "dossier_source_hash_mismatch"})
		default:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "dossier_unavailable"})
		}
		return
	}
	bundle, canonical, err := assembleDossierBundle(snapshot)
	if err != nil {
		code := "dossier_assembly_failed"
		if errors.Is(err, errDossierReferenceMissing) {
			code = "dossier_evidence_reference_missing"
		} else if errors.Is(err, errDossierAcceptanceMissing) {
			code = "dossier_actor_acceptance_missing"
		}
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": code, "message": err.Error()})
		return
	}
	if stored, ok := h.loadStoredDossierBytes(r.Context(), bundle.CaseRef); ok {
		writeDossierJSON(w, stored)
		return
	}
	if err := h.storeDossierBundle(r.Context(), snapshot, bundle, canonical, dossierRequester(r)); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "dossier_store_failed"})
		return
	}
	stored, ok := h.loadStoredDossierBytes(r.Context(), bundle.CaseRef)
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "dossier_store_verification_failed"})
		return
	}
	writeDossierJSON(w, stored)
}

func assembleDossierBundle(snapshot dossierSnapshot) (dossierBundle, []byte, error) {
	if snapshot.Report == nil || strings.TrimSpace(snapshot.Mint) == "" || strings.TrimSpace(snapshot.VerdictSignature) == "" {
		return dossierBundle{}, nil, errDossierSourceIncomplete
	}
	final := dossierMap(snapshot.Report["final_verdict"])
	verdictSignature := strings.TrimSpace(dossierString(final["signature"]))
	if verdictSignature == "" {
		return dossierBundle{}, nil, errDossierSourceIncomplete
	}
	rows := buildDossierSignalRows(snapshot.Report)
	actorCase := isActorDossierReport(snapshot.Report)
	if actorCase {
		if len(dossierMap(snapshot.Report["actor_acceptance"])) == 0 {
			return dossierBundle{}, nil, errDossierAcceptanceMissing
		}
		if err := validateActorDossierRows(rows); err != nil {
			return dossierBundle{}, nil, err
		}
	} else {
		for _, row := range rows {
			if (row.State == "verified" || row.State == "observed") && !dossierRefsPresent(row.Refs) {
				return dossierBundle{}, nil, fmt.Errorf("%w: %s", errDossierReferenceMissing, row.ID)
			}
		}
	}

	caseRef := dossierCaseRef(snapshot.Mint, snapshot.VerdictSignature)
	body := dossierBody{
		DossierVersion:      dossierVersion,
		CaseRef:             caseRef,
		ProducedAt:          snapshot.ProducedAt.UTC(),
		SourceSnapshotHash: snapshot.SourceHash,
		Verdict:             snapshot.Report["final_verdict"],
		VerdictCard: map[string]any{
			"mapper_id":      "koschei-verdict-card",
			"mapper_version": dossierMapperVersion,
			"signal_rows":    rows,
		},
		TechnicalReport: snapshot.Report,
		Verification: map[string]any{
			"verifier_repo_url": dossierVerifierRepo,
			"verdict_signature": verdictSignature,
			"snapshot_identity": snapshot.VerdictSignature,
			"hash_algorithm": "SHA-256",
			"bundle_hash_scope": "UTF-8 JSON encoding of the dossier body with bundle_hash excluded; Go struct field order is fixed and map keys are lexicographically sorted by encoding/json.",
			"case_ref_rule": "KD1- + lower-case base32(no padding) of the first 20 SHA-256 bytes of target_id + newline + snapshot_identity.",
			"command": "node oss/verifier/typescript/verify-dossier.mjs ./dossier.json",
		},
		Limitations: append([]string{}, dossierLimitations...),
	}
	if actorCase {
		body.Target = actorDossierTarget(snapshot)
		body.VerdictCard = map[string]any{
			"mapper_id":      "koschei-actor-acceptance-card",
			"mapper_version": dossierActorMapperVersion,
			"signal_rows":    rows,
		}
		body.ActorDossier = snapshot.Report["actor_investigation"]
		body.ActorAcceptance = snapshot.Report["actor_acceptance"]
		body.CreatedTokenHistory = actorDossierCreatedTokens(snapshot.Report)
		body.FundingOrigin = actorDossierFundingOrigin(snapshot.Report)
		body.CrossTokenConnections = actorDossierConnections(snapshot.Report)
		body.EvidenceLog = actorDossierEvidenceLog(snapshot.Report)
		body.SectionLimitations = actorDossierSectionLimitations(snapshot.Report)
	} else {
		body.Target = map[string]any{"kind": "token_mint", "id": snapshot.Mint, "network": snapshot.Network}
		body.Token = map[string]any{
			"mint":            snapshot.Mint,
			"network":         snapshot.Network,
			"market_snapshot": snapshot.Report["market"],
			"launch_metadata": snapshot.Report["launch_forensics"],
			"source_context":  snapshot.Report["source_context"],
		}
		body.ThreatAnticipation = snapshot.Report["threat_anticipation"]
		body.EvidenceArms = dossierFirst(snapshot.Report["evidence_arms"], snapshot.Report["modules"], []any{})
		body.TransactionEvidence = dossierFirst(snapshot.Report["transaction_evidence"], []any{})
		body.EvidenceReferences = dossierFirst(snapshot.Report["evidence_references"], map[string]any{})
		body.ActorDossier = snapshot.Report["actor_investigation"]
		body.HolderContext = snapshot.Report["holder_concentration_context"]
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return dossierBundle{}, nil, err
	}
	bundle := dossierBundle{dossierBody: body, BundleHash: dossierSHA256(bodyBytes)}
	canonical, err := json.Marshal(bundle)
	if err != nil {
		return dossierBundle{}, nil, err
	}
	return bundle, canonical, nil
}

func writeDossierJSON(w http.ResponseWriter, canonical []byte) {
	var bundle dossierBundle
	if json.Unmarshal(canonical, &bundle) != nil || bundle.CaseRef == "" || bundle.BundleHash == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "dossier_canonical_bundle_invalid"})
		return
	}
	publicPath := "/dossier/" + bundle.CaseRef
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=koschei-%s.json", bundle.CaseRef))
	w.Header().Set("ETag", `"`+bundle.BundleHash+`"`)
	w.Header().Set("Content-Location", publicPath)
	w.Header().Set("Link", `<`+publicPath+`>; rel="alternate"; type="text/html"`)
	w.Header().Set("X-Koschei-Case-Ref", bundle.CaseRef)
	w.Header().Set("X-Koschei-Public-Dossier", publicPath)
	_, _ = w.Write(canonical)
}

func (h *Handler) storeDossierBundle(ctx context.Context, snapshot dossierSnapshot, bundle dossierBundle, canonical []byte, requestedBy string) error {
	if h == nil || h.DB == nil {
		return errDossierSourceIncomplete
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	_, err = h.DB.ExecContext(ctx, `
		INSERT INTO dossier_exports
		(case_ref,mint,verdict_id,verdict_signature,source_snapshot_id,bundle_hash,canonical_bundle,bundle_json,requested_by)
		VALUES ($1,$2,NULLIF($3,''),$4,$5::uuid,$6,$7,$8::jsonb,$9)
		ON CONFLICT (case_ref) DO NOTHING`,
		bundle.CaseRef, snapshot.Mint, snapshot.VerdictID, snapshot.VerdictSignature,
		snapshot.ID, bundle.BundleHash, canonical, string(raw), strings.TrimSpace(requestedBy),
	)
	return err
}

func (h *Handler) loadStoredDossierBytes(ctx context.Context, caseRef string) ([]byte, bool) {
	if h == nil || h.DB == nil {
		return nil, false
	}
	var raw []byte
	if h.DB.QueryRowContext(ctx, `SELECT canonical_bundle FROM dossier_exports WHERE case_ref=$1`, caseRef).Scan(&raw) != nil {
		return nil, false
	}
	return raw, len(raw) > 0
}

func dossierRequester(r *http.Request) string {
	if principal, ok := apiPrincipalFromContext(r.Context()); ok {
		return "api_key:" + strings.TrimSpace(principal.KeyID)
	}
	if user, ok := userFromContext(r.Context()); ok {
		return "user:" + strings.TrimSpace(user.Sub)
	}
	return "owner"
}
