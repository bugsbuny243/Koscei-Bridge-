package handlers

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/defense"
	"koschei/api/internal/router"
)

func (h *Handler) OwnerDefenseArtifacts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		items, err := defense.ListArtifacts(r.Context(), h.DB, r.URL.Query().Get("program_id"), r.URL.Query().Get("network"), limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "artifact_list_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "artifacts": items})
	case http.MethodPost:
		var input defense.ArtifactInput
		if err := decodeJSON(r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_artifact"})
			return
		}
		input.CreatedBy = "owner"
		item, err := defense.StoreArtifact(r.Context(), h.DB, input)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "artifact_rejected", "details": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "artifact": item})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) OwnerDefenseKnowledge(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		query := strings.TrimSpace(r.URL.Query().Get("q"))
		framework := strings.TrimSpace(r.URL.Query().Get("framework"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		embedding := []float64{}
		if query != "" && envBool("KOSCHEI_DEFENSE_KNOWLEDGE_EMBEDDINGS_ENABLED", false) {
			if result, err := router.Embed(r.Context(), router.EmbedRequest{Input: query}); err == nil {
				embedding = result.Embedding
			}
		}
		items, err := defense.SearchKnowledge(r.Context(), h.DB, query, framework, embedding, limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "knowledge_search_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "documents": items, "embedding_used": len(embedding) > 0})
	case http.MethodPost:
		var input defense.KnowledgeInput
		if err := decodeJSON(r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_knowledge_document"})
			return
		}
		input.CreatedBy = "owner"
		if envBool("KOSCHEI_DEFENSE_KNOWLEDGE_EMBEDDINGS_ENABLED", false) {
			if result, err := router.Embed(r.Context(), router.EmbedRequest{Input: input.Title + "\n" + input.Body}); err == nil {
				input.Embedding, input.EmbeddingModel = result.Embedding, result.Model
			}
		}
		doc, err := defense.StoreKnowledge(r.Context(), h.DB, input)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "knowledge_rejected", "details": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "document": doc})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type defenseLabRequest struct {
	Action              string            `json:"action"`
	ArtifactRef         string            `json:"artifact_ref"`
	FindingRef          string            `json:"finding_ref"`
	PatchRef            string            `json:"patch_ref"`
	ApprovalReason      string            `json:"approval_reason"`
	Mutation            string            `json:"mutation"`
	Commands            []string          `json:"commands"`
	Replacements        map[string]string `json:"replacements"`
	BenchmarkName       string            `json:"benchmark_name"`
	BenchmarkCategory   string            `json:"benchmark_category"`
	ExpectedRules       []string          `json:"expected_rules"`
	ExpectedAbsentRules []string          `json:"expected_absent_rules"`
	BenchmarkCaseRef    string            `json:"benchmark_case_ref"`
}

type patchFileProposal struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Reason  string `json:"reason"`
}

type patchProposal struct {
	Summary     string              `json:"summary"`
	Files       []patchFileProposal `json:"files"`
	Tests       []string            `json:"tests"`
	Limitations []string            `json:"limitations"`
}

func (h *Handler) OwnerDefenseLab(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input defenseLabRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_lab_request"})
		return
	}
	switch strings.ToLower(strings.TrimSpace(input.Action)) {
	case "analyze":
		h.ownerDefenseAnalyze(w, r, input)
	case "verify":
		h.ownerDefenseVerify(w, r, input, nil)
	case "patch_propose":
		h.ownerDefensePatchPropose(w, r, input)
	case "patch_approve":
		h.ownerDefensePatchApprove(w, r, input)
	case "patch_verify":
		h.ownerDefensePatchVerify(w, r, input)
	case "mutate":
		h.ownerDefenseMutate(w, r, input)
	case "benchmark_create":
		h.ownerDefenseBenchmarkCreate(w, r, input)
	case "evaluate":
		h.ownerDefenseEvaluate(w, r, input)
	case "dataset_export":
		h.ownerDefenseDatasetExport(w, r)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_lab_action"})
	}
}

func (h *Handler) ownerDefenseAnalyze(w http.ResponseWriter, r *http.Request, input defenseLabRequest) {
	artifact, err := defense.LoadArtifact(r.Context(), h.DB, input.ArtifactRef)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "artifact_not_found"})
		return
	}
	report, err := defense.AnalyzeArtifact(artifact)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "analysis_failed", "details": err.Error()})
		return
	}
	if err = defense.PersistLabReport(r.Context(), h.DB, report); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "analysis_persist_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "report": report, "verdict_authority": false})
}

func (h *Handler) runDefenseVerification(r *http.Request, input defenseLabRequest, replacements map[string]string) (defense.VerificationReport, error) {
	artifact, err := defense.LoadArtifact(r.Context(), h.DB, input.ArtifactRef)
	if err != nil {
		return defense.VerificationReport{}, err
	}
	if replacements == nil {
		replacements = input.Replacements
	}
	report, err := defense.VerifyBundle(r.Context(), artifact, input.FindingRef, input.PatchRef, replacements, input.Commands, envBool("KOSCHEI_DEFENSE_SANDBOX_ENABLED", false))
	if err != nil {
		return report, err
	}
	if err = defense.PersistVerification(r.Context(), h.DB, report); err != nil {
		return report, err
	}
	return report, nil
}

func (h *Handler) ownerDefenseVerify(w http.ResponseWriter, r *http.Request, input defenseLabRequest, replacements map[string]string) {
	report, err := h.runDefenseVerification(r, input, replacements)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "verification_failed", "details": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "verification": report})
}

func (h *Handler) ownerDefensePatchPropose(w http.ResponseWriter, r *http.Request, input defenseLabRequest) {
	if !envBool("KOSCHEI_DEFENSE_PATCH_PROPOSAL_ENABLED", false) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "patch_proposal_disabled"})
		return
	}
	artifact, err := defense.LoadArtifact(r.Context(), h.DB, input.ArtifactRef)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "artifact_not_found"})
		return
	}
	source := string(artifact.Content)
	if len(source) > 120000 {
		source = source[:120000]
	}
	prompt := `Return only JSON matching this exact schema: {"summary":"","files":[{"path":"relative/path.rs","content":"complete replacement UTF-8 content","reason":""}],"tests":["cargo test"],"limitations":[]}. Propose the smallest defensive patch. Never create deployment, wallet, private-key, transaction-sending or mainnet-execution code. Do not claim the patch is verified. Artifact ref: ` + artifact.ArtifactRef + `. Finding ref: ` + input.FindingRef + `. Source bundle JSON:\n` + source
	response, err := router.Chat(r.Context(), router.ChatRequest{
		System:      "You are Koschei Defense Engineer. Produce a review-only patch proposal. The deterministic Koschei engine and sandbox verification remain authoritative.",
		Prompt:      prompt,
		Model:       strings.TrimSpace(os.Getenv("TOGETHER_MODEL_DEFENSE_ENGINEER")),
		MaxTokens:   6000,
		Temperature: 0.1,
		Timeout:     45 * time.Second,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "patch_provider_failed"})
		return
	}
	var proposal patchProposal
	if err = router.DecodeJSONObject(response.Content, &proposal); err != nil || len(proposal.Files) == 0 {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "invalid_patch_proposal"})
		return
	}
	if len(proposal.Files) > 20 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "patch_too_large"})
		return
	}
	for _, file := range proposal.Files {
		path := strings.TrimSpace(file.Path)
		if path == "" || len(file.Content) > 300000 || strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsafe_patch_file"})
			return
		}
	}
	encoded, _ := json.Marshal(proposal)
	hash := handlerSHA256(encoded)
	ref := "KDP1-" + strings.TrimPrefix(hash, "sha256:")[:32]
	_, err = h.DB.ExecContext(r.Context(), `INSERT INTO defense_patch_proposals
		(patch_ref,program_id,network,finding_ref,source_artifact_ref,provider,model,proposal_json,proposal_hash,human_approved,applied_to_production,created_by)
		VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8::jsonb,$9,false,false,'owner') ON CONFLICT(patch_ref) DO NOTHING`,
		ref, artifact.ProgramID, artifact.Network, input.FindingRef, artifact.ArtifactRef, response.Provider, response.Model, string(encoded), hash)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "patch_persist_failed"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":                      true,
		"patch_ref":               ref,
		"proposal":                proposal,
		"human_approval_required": true,
		"verified":                false,
		"applied_to_production":   false,
	})
}

func (h *Handler) ownerDefensePatchApprove(w http.ResponseWriter, r *http.Request, input defenseLabRequest) {
	input.PatchRef = strings.TrimSpace(input.PatchRef)
	input.ApprovalReason = strings.TrimSpace(input.ApprovalReason)
	if input.PatchRef == "" || input.ApprovalReason == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "approval_reason_required"})
		return
	}
	var exists bool
	if err := h.DB.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM defense_patch_proposals WHERE patch_ref=$1)`, input.PatchRef).Scan(&exists); err != nil || !exists {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "patch_not_found"})
		return
	}
	hash := handlerHash(map[string]any{"patch_ref": input.PatchRef, "reason": input.ApprovalReason, "approved_by": "owner"})
	ref := "KPA1-" + strings.TrimPrefix(hash, "sha256:")[:32]
	_, err := h.DB.ExecContext(r.Context(), `INSERT INTO defense_patch_approvals(approval_ref,patch_ref,approved_by,approval_reason,approval_hash) VALUES($1,$2,'owner',$3,$4) ON CONFLICT(approval_ref) DO NOTHING`, ref, input.PatchRef, input.ApprovalReason, hash)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "approval_persist_failed"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "approval_ref": ref, "patch_ref": input.PatchRef, "production_apply_authorized": false})
}

func (h *Handler) ownerDefensePatchVerify(w http.ResponseWriter, r *http.Request, input defenseLabRequest) {
	input.PatchRef = strings.TrimSpace(input.PatchRef)
	var approved bool
	if err := h.DB.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM defense_patch_approvals WHERE patch_ref=$1)`, input.PatchRef).Scan(&approved); err != nil || !approved {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "patch_human_approval_required"})
		return
	}
	var artifactRef, findingRef string
	var raw []byte
	if err := h.DB.QueryRowContext(r.Context(), `SELECT source_artifact_ref,COALESCE(finding_ref,''),proposal_json FROM defense_patch_proposals WHERE patch_ref=$1`, input.PatchRef).Scan(&artifactRef, &findingRef, &raw); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "patch_not_found"})
		return
	}
	var proposal patchProposal
	if json.Unmarshal(raw, &proposal) != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "patch_corrupt"})
		return
	}
	replacements := map[string]string{}
	for _, file := range proposal.Files {
		replacements[file.Path] = file.Content
	}
	input.ArtifactRef, input.FindingRef = artifactRef, findingRef
	input.Commands = proposal.Tests
	if len(input.Commands) == 0 {
		input.Commands = []string{"cargo test"}
	}
	report, err := h.runDefenseVerification(r, input, replacements)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "patch_verification_failed", "details": err.Error()})
		return
	}
	proof := map[string]any{}
	if findingRef != "" {
		proof, err = h.persistProofOfFix(r, input.PatchRef, findingRef, report)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "proof_of_fix_persist_failed"})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "verification": report, "proof_of_fix": proof, "applied_to_production": false})
}

func (h *Handler) persistProofOfFix(r *http.Request, patchRef, findingRef string, verification defense.VerificationReport) (map[string]any, error) {
	status := map[string]string{
		"passed":           "partial",
		"failed":           "failed",
		"partial":          "partial",
		"blocked":          "blocked",
		"tool_unavailable": "blocked",
	}[verification.Status]
	if status == "" {
		status = "partial"
	}
	var before, beforeStatus sql.NullString
	_ = h.DB.QueryRowContext(r.Context(), `SELECT verification_ref,status FROM defense_verification_runs WHERE finding_ref=$1 AND patch_ref IS NULL ORDER BY created_at DESC LIMIT 1`, findingRef).Scan(&before, &beforeStatus)
	evidence := []string{
		"verification:" + verification.VerificationRef,
		"patch:" + patchRef,
		"artifact:" + verification.SourceArtifactRef,
	}
	limitations := append([]string{}, verification.Limitations...)
	limitations = append(limitations, "Generic build or test success is not proof that an exploit path was closed. Verified proof-of-fix requires a versioned reproduction invariant with an unpatched baseline and a patched counter-run.")
	if !before.Valid {
		limitations = append(limitations, "No unpatched baseline verification was bound to this finding.")
	} else {
		evidence = append(evidence, "baseline_verification:"+before.String, "baseline_status:"+beforeStatus.String)
	}
	payload := map[string]any{
		"program_id":  verification.ProgramID,
		"finding_ref": findingRef,
		"patch_ref":   patchRef,
		"before":      before.String,
		"after":       verification.VerificationRef,
		"status":      status,
		"evidence":    evidence,
		"limitations": limitations,
	}
	hash := handlerHash(payload)
	ref := "KPF1-" + strings.TrimPrefix(hash, "sha256:")[:32]
	evidenceRaw, _ := json.Marshal(evidence)
	limitationsRaw, _ := json.Marshal(limitations)
	_, err := h.DB.ExecContext(r.Context(), `INSERT INTO defense_proof_of_fix
		(proof_ref,program_id,network,finding_ref,patch_ref,before_verification_ref,after_verification_ref,status,evidence_refs,limitations,proof_hash,verdict_authority)
		VALUES($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9::jsonb,$10::jsonb,$11,false) ON CONFLICT(proof_ref) DO NOTHING`,
		ref, verification.ProgramID, verification.Network, findingRef, patchRef, before.String, verification.VerificationRef, status, string(evidenceRaw), string(limitationsRaw), hash)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"proof_ref":         ref,
		"status":            status,
		"proof_hash":        hash,
		"verdict_authority": false,
		"verified_eligible": false,
	}, nil
}

func (h *Handler) ownerDefenseMutate(w http.ResponseWriter, r *http.Request, input defenseLabRequest) {
	artifact, err := defense.LoadArtifact(r.Context(), h.DB, input.ArtifactRef)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "artifact_not_found"})
		return
	}
	candidate, err := defense.SyntheticMutation(artifact, input.Mutation)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "mutation_failed", "details": err.Error()})
		return
	}
	stored, err := defense.StoreArtifact(r.Context(), h.DB, candidate)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "mutation_persist_failed"})
		return
	}
	_ = h.persistTrainingExample(
		r,
		"synthetic_mutation",
		artifact.ProgramID,
		map[string]any{"parent_artifact_ref": artifact.ArtifactRef, "mutation": input.Mutation},
		map[string]any{"synthetic_artifact_ref": stored.ArtifactRef, "production_eligible": false},
		[]string{"artifact:" + artifact.ArtifactRef, "artifact:" + stored.ArtifactRef},
		"candidate",
	)
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "artifact": stored, "production_eligible": false})
}

func (h *Handler) ownerDefenseBenchmarkCreate(w http.ResponseWriter, r *http.Request, input defenseLabRequest) {
	artifact, err := defense.LoadArtifact(r.Context(), h.DB, input.ArtifactRef)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "artifact_not_found"})
		return
	}
	payload := map[string]any{
		"name":     input.BenchmarkName,
		"category": input.BenchmarkCategory,
		"artifact": input.ArtifactRef,
		"expected": input.ExpectedRules,
		"absent":   input.ExpectedAbsentRules,
	}
	ref := "KBC1-" + strings.TrimPrefix(handlerHash(payload), "sha256:")[:32]
	expected, _ := json.Marshal(input.ExpectedRules)
	absent, _ := json.Marshal(input.ExpectedAbsentRules)
	_, err = h.DB.ExecContext(r.Context(), `INSERT INTO defense_benchmark_cases
		(case_ref,name,category,program_id,network,source_artifact_ref,expected_rules,expected_absent_rules,metadata,created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,'{}'::jsonb,'owner') ON CONFLICT(case_ref) DO NOTHING`,
		ref, strings.TrimSpace(input.BenchmarkName), strings.TrimSpace(input.BenchmarkCategory), artifact.ProgramID, artifact.Network, artifact.ArtifactRef, string(expected), string(absent))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "benchmark_rejected", "details": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "benchmark_case_ref": ref})
}

func (h *Handler) ownerDefenseEvaluate(w http.ResponseWriter, r *http.Request, input defenseLabRequest) {
	var artifactRef string
	var expectedRaw, absentRaw []byte
	if err := h.DB.QueryRowContext(r.Context(), `SELECT source_artifact_ref,expected_rules,expected_absent_rules FROM defense_benchmark_cases WHERE case_ref=$1`, strings.TrimSpace(input.BenchmarkCaseRef)).Scan(&artifactRef, &expectedRaw, &absentRaw); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "benchmark_not_found"})
		return
	}
	artifact, err := defense.LoadArtifact(r.Context(), h.DB, artifactRef)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "artifact_not_found"})
		return
	}
	report, err := defense.AnalyzeArtifact(artifact)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "analysis_failed"})
		return
	}
	expected, absent := []string{}, []string{}
	_ = json.Unmarshal(expectedRaw, &expected)
	_ = json.Unmarshal(absentRaw, &absent)
	observed := []string{}
	for _, finding := range report.Findings {
		observed = append(observed, finding.RuleID)
	}
	metrics := defense.EvaluateRules(expected, absent, observed)
	status := "failed"
	if metrics.Passed {
		status = "passed"
	}
	resultPayload := map[string]any{
		"case":     input.BenchmarkCaseRef,
		"detector": defense.DetectorVersion,
		"observed": observed,
		"metrics":  metrics,
	}
	hash := handlerHash(resultPayload)
	ref := "KEV1-" + strings.TrimPrefix(hash, "sha256:")[:32]
	observedRaw, _ := json.Marshal(observed)
	metricsRaw, _ := json.Marshal(metrics)
	_, err = h.DB.ExecContext(r.Context(), `INSERT INTO defense_evaluation_runs
		(evaluation_ref,benchmark_case_ref,detector_version,observed_rules,metrics,status,result_hash)
		VALUES($1,$2,$3,$4::jsonb,$5::jsonb,$6,$7) ON CONFLICT(evaluation_ref) DO NOTHING`,
		ref, input.BenchmarkCaseRef, defense.DetectorVersion, string(observedRaw), string(metricsRaw), status, hash)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "evaluation_persist_failed"})
		return
	}
	if metrics.Passed {
		_ = h.persistTrainingExample(
			r,
			"hard_negative",
			artifact.ProgramID,
			map[string]any{"benchmark_case_ref": input.BenchmarkCaseRef, "artifact_ref": artifact.ArtifactRef},
			map[string]any{"detector_version": defense.DetectorVersion, "observed_rules": observed, "metrics": metrics},
			[]string{"benchmark:" + input.BenchmarkCaseRef, "evaluation:" + ref},
			"benchmark_passed",
		)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "evaluation_ref": ref, "status": status, "metrics": metrics, "observed_rules": observed})
}

func (h *Handler) persistTrainingExample(r *http.Request, kind, programID string, input, output map[string]any, provenance []string, quality string) error {
	payload := map[string]any{
		"source_kind": kind,
		"program_id":  programID,
		"input":       input,
		"output":      output,
		"provenance":  provenance,
		"quality":     quality,
	}
	hash := handlerHash(payload)
	ref := "KTE1-" + strings.TrimPrefix(hash, "sha256:")[:32]
	inputRaw, _ := json.Marshal(input)
	outputRaw, _ := json.Marshal(output)
	provenanceRaw, _ := json.Marshal(provenance)
	_, err := h.DB.ExecContext(r.Context(), `INSERT INTO defense_training_examples
		(example_ref,source_kind,program_id,input_json,output_json,provenance_refs,quality_status,example_hash)
		VALUES($1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb,$7,$8) ON CONFLICT(example_ref) DO NOTHING`,
		ref, kind, programID, string(inputRaw), string(outputRaw), string(provenanceRaw), quality, hash)
	return err
}

func (h *Handler) ownerDefenseDatasetExport(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `SELECT example_ref,source_kind,program_id,input_json,output_json,provenance_refs,quality_status,example_hash,created_at
		FROM defense_training_examples WHERE quality_status IN ('human_reviewed','benchmark_passed') ORDER BY created_at DESC LIMIT 1000`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dataset_query_failed"})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var ref, kind, program, quality, hash string
		var inputRaw, outputRaw, provenanceRaw []byte
		var created time.Time
		if rows.Scan(&ref, &kind, &program, &inputRaw, &outputRaw, &provenanceRaw, &quality, &hash, &created) != nil {
			continue
		}
		var input, output map[string]any
		var provenance []string
		_ = json.Unmarshal(inputRaw, &input)
		_ = json.Unmarshal(outputRaw, &output)
		_ = json.Unmarshal(provenanceRaw, &provenance)
		items = append(items, map[string]any{
			"example_ref":     ref,
			"source_kind":     kind,
			"program_id":      program,
			"input":           input,
			"output":          output,
			"provenance_refs": provenance,
			"quality_status":  quality,
			"example_hash":    hash,
			"created_at":      created,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"schema_version": "koschei-defense-training-export-v1",
		"examples":       items,
		"count":          len(items),
	})
}

func handlerSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func handlerHash(value any) string {
	data, _ := json.Marshal(value)
	return handlerSHA256(data)
}
