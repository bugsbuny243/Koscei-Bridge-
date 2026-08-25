package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"koschei/api/internal/defense"
	"koschei/api/internal/executioncontainment"
	"koschei/api/internal/executionproof"
	"koschei/api/internal/securityevidence"
)

const (
	defenseValidationAPIMaxScenarioBytes = 256 << 10
	defenseValidationAPIMaxControls      = 8
	defenseValidationAPIMaxCases         = 64
	defenseValidationAPIMaxActionBytes   = 128 << 10

	defenseValidationTrustedCollectorsEnv = "KOSCHEI_DEFENSE_VALIDATION_TRUSTED_COLLECTORS_JSON"
)

type defenseValidationAPIRequest struct {
	RunRef   string                        `json:"run_ref"`
	Scenario json.RawMessage               `json:"scenario"`
	Controls []defenseValidationAPIControl `json:"controls"`
	Cases    []defenseValidationAPICase    `json:"cases"`
}

type defenseValidationAPIControl struct {
	ControlRef         string `json:"control_ref"`
	CollectorRef       string `json:"collector_ref"`
	CollectorPublicKey string `json:"collector_public_key"`
}

type defenseValidationAPIAction struct {
	Kind            string `json:"kind"`
	CanonicalBase64 string `json:"canonical_base64"`
}

type defenseValidationAPICase struct {
	CaseRef             string                                          `json:"case_ref"`
	CaseKind            string                                          `json:"case_kind"`
	TechniqueID         string                                          `json:"technique_id"`
	ControlRef          string                                          `json:"control_ref"`
	ExecutionMode       string                                          `json:"execution_mode"`
	ImpactOffsetMS      *int64                                          `json:"impact_offset_ms,omitempty"`
	ObservationWindowMS int64                                           `json:"observation_window_ms"`
	ContainmentReceipt  executioncontainment.Receipt                    `json:"containment_receipt"`
	ExecutionProof      executionproof.Proof                            `json:"execution_proof"`
	ApprovedAction      defenseValidationAPIAction                      `json:"approved_action"`
	CandidateAction     defenseValidationAPIAction                      `json:"candidate_action"`
	ObservationBinding  *defense.DefenseValidationObservationBindingV02 `json:"observation_binding,omitempty"`
	ObservationEvent    *securityevidence.Event                         `json:"observation_event,omitempty"`
}

type defenseValidationAPIResponse struct {
	OK                        bool                               `json:"ok"`
	Product                   string                             `json:"product"`
	EvidenceModel             string                             `json:"evidence_model"`
	ScenarioContractHash      string                             `json:"scenario_contract_hash"`
	VerifiedExecutions        int                                `json:"verified_executions"`
	VerifiedObservations      int                                `json:"verified_observations"`
	Report                    defense.DefenseValidationReportV02 `json:"report"`
	MainnetTransactionSent    bool                               `json:"mainnet_transaction_sent"`
	ExecutionAuthority        bool                               `json:"execution_authority"`
	ProductionControlMutation bool                               `json:"production_control_mutation"`
	Limitations               []string                           `json:"limitations"`
}

// DefenseValidationV1 validates an already-collected, isolated defense test run.
// It never runs arbitrary commands, submits a transaction, mutates a production
// control, or trusts caller-asserted VERIFIED state. Execution receipts, proof
// envelopes and independent collector events are recomputed and authenticated
// before they can contribute to the deterministic validation report.
func (h *Handler) DefenseValidationV1(w http.ResponseWriter, r *http.Request) {
	var input defenseValidationAPIRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "code": "invalid_request", "message": "Invalid defense validation request.",
		})
		return
	}

	trustedCollectors, err := trustedDefenseValidationCollectorsFromEnv()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "code": "defense_validation_trust_unavailable", "message": "Defense validation collector trust is unavailable.",
		})
		return
	}
	if err := validateDefenseValidationAPICollectorTrust(input.Controls, trustedCollectors); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "code": "defense_validation_evidence_rejected", "message": err.Error(),
		})
		return
	}

	result, err := evaluateDefenseValidationAPIRequest(input)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "code": "defense_validation_evidence_rejected", "message": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func trustedDefenseValidationCollectorsFromEnv() (map[string]string, error) {
	raw := strings.TrimSpace(os.Getenv(defenseValidationTrustedCollectorsEnv))
	if raw == "" {
		return nil, errors.New("trusted collector registry is not configured")
	}
	configured := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &configured); err != nil {
		return nil, errors.New("trusted collector registry must be a JSON object")
	}
	if len(configured) == 0 {
		return nil, errors.New("trusted collector registry is empty")
	}

	trusted := make(map[string]string, len(configured))
	for rawRef, rawKey := range configured {
		collectorRef := strings.TrimSpace(rawRef)
		collectorPublicKey := strings.TrimSpace(rawKey)
		if collectorRef == "" || collectorPublicKey == "" {
			return nil, errors.New("trusted collector registry entries require non-empty collector refs and public keys")
		}
		if _, exists := trusted[collectorRef]; exists {
			return nil, fmt.Errorf("duplicate trusted collector_ref %q", collectorRef)
		}
		if _, err := defense.NewExecutionIntegrityControlV02("trust-registry:"+collectorRef, collectorRef, defense.DefenseValidationExecutionIntegrityConfigV02{
			CollectorPublicKey:           collectorPublicKey,
			IndependentCollectorRequired: true,
			MainnetSubmissionAllowed:     false,
			ProductionWiringClaim:        false,
		}); err != nil {
			return nil, fmt.Errorf("trusted collector %q is invalid: %w", collectorRef, err)
		}
		trusted[collectorRef] = collectorPublicKey
	}
	return trusted, nil
}

func validateDefenseValidationAPICollectorTrust(controls []defenseValidationAPIControl, trustedCollectors map[string]string) error {
	if len(trustedCollectors) == 0 {
		return errors.New("trusted collector registry is unavailable")
	}
	for _, raw := range controls {
		controlRef := strings.TrimSpace(raw.ControlRef)
		collectorRef := strings.TrimSpace(raw.CollectorRef)
		suppliedPublicKey := strings.TrimSpace(raw.CollectorPublicKey)
		trustedPublicKey, ok := trustedCollectors[collectorRef]
		if !ok {
			return fmt.Errorf("control %q references untrusted collector %q", controlRef, collectorRef)
		}
		if suppliedPublicKey != trustedPublicKey {
			return fmt.Errorf("control %q collector public key does not match the server trust registry", controlRef)
		}
	}
	return nil
}

func evaluateDefenseValidationAPIRequest(input defenseValidationAPIRequest) (defenseValidationAPIResponse, error) {
	input.RunRef = strings.TrimSpace(input.RunRef)
	if input.RunRef == "" {
		return defenseValidationAPIResponse{}, errors.New("run_ref is required")
	}
	if len(input.Scenario) == 0 || len(input.Scenario) > defenseValidationAPIMaxScenarioBytes {
		return defenseValidationAPIResponse{}, errors.New("scenario is required and must be at most 256 KiB")
	}
	if len(input.Controls) == 0 || len(input.Controls) > defenseValidationAPIMaxControls {
		return defenseValidationAPIResponse{}, fmt.Errorf("controls must contain between 1 and %d entries", defenseValidationAPIMaxControls)
	}
	if len(input.Cases) > defenseValidationAPIMaxCases {
		return defenseValidationAPIResponse{}, fmt.Errorf("cases may contain at most %d entries", defenseValidationAPIMaxCases)
	}

	scenario, err := defense.ParseDefenseValidationScenarioV02(input.Scenario)
	if err != nil {
		return defenseValidationAPIResponse{}, fmt.Errorf("scenario contract rejected: %w", err)
	}
	scenarioHash, err := defense.DefenseValidationScenarioDigestV02(scenario)
	if err != nil {
		return defenseValidationAPIResponse{}, fmt.Errorf("scenario contract digest: %w", err)
	}

	controls := make([]defense.DefenseValidationControlV02, 0, len(input.Controls))
	controlByRef := make(map[string]defense.DefenseValidationControlV02, len(input.Controls))
	for _, raw := range input.Controls {
		controlRef := strings.TrimSpace(raw.ControlRef)
		collectorRef := strings.TrimSpace(raw.CollectorRef)
		if controlRef == "" || collectorRef == "" || strings.TrimSpace(raw.CollectorPublicKey) == "" {
			return defenseValidationAPIResponse{}, errors.New("each control requires control_ref, collector_ref and collector_public_key")
		}
		if _, exists := controlByRef[controlRef]; exists {
			return defenseValidationAPIResponse{}, fmt.Errorf("duplicate control_ref %q", controlRef)
		}
		control, err := defense.NewExecutionIntegrityControlV02(controlRef, collectorRef, defense.DefenseValidationExecutionIntegrityConfigV02{
			CollectorPublicKey:           strings.TrimSpace(raw.CollectorPublicKey),
			IndependentCollectorRequired: true,
			MainnetSubmissionAllowed:     false,
			ProductionWiringClaim:        false,
		})
		if err != nil {
			return defenseValidationAPIResponse{}, fmt.Errorf("control %q rejected: %w", controlRef, err)
		}
		controlByRef[controlRef] = control
		controls = append(controls, control)
	}

	cases := make([]defense.DefenseValidationCaseV02, 0, len(input.Cases))
	observations := make([]defense.DefenseValidationObservationV02, 0, len(input.Cases))
	chainID := uint64(0)
	for _, raw := range input.Cases {
		controlRef := strings.TrimSpace(raw.ControlRef)
		control, ok := controlByRef[controlRef]
		if !ok {
			return defenseValidationAPIResponse{}, fmt.Errorf("case %q references unknown control %q", strings.TrimSpace(raw.CaseRef), controlRef)
		}
		approvedAction, err := decodeDefenseValidationAPIAction(raw.ApprovedAction)
		if err != nil {
			return defenseValidationAPIResponse{}, fmt.Errorf("case %q approved_action: %w", strings.TrimSpace(raw.CaseRef), err)
		}
		candidateAction, err := decodeDefenseValidationAPIAction(raw.CandidateAction)
		if err != nil {
			return defenseValidationAPIResponse{}, fmt.Errorf("case %q candidate_action: %w", strings.TrimSpace(raw.CaseRef), err)
		}

		execution, err := defense.AdaptExecutionIntegrityCaseV02(defense.DefenseValidationExecutionAdapterInputV02{
			CaseRef:                strings.TrimSpace(raw.CaseRef),
			CaseKind:               strings.TrimSpace(raw.CaseKind),
			TechniqueID:            strings.TrimSpace(raw.TechniqueID),
			ExecutionMode:          strings.TrimSpace(raw.ExecutionMode),
			ImpactOffsetMS:         raw.ImpactOffsetMS,
			ObservationWindowMS:    raw.ObservationWindowMS,
			MainnetTransactionSent: false,
			Control:                control,
			Scenario:               scenario,
			ContainmentReceipt:     raw.ContainmentReceipt,
			ExecutionProof:         raw.ExecutionProof,
			ApprovedSafeAction:     approvedAction,
			CandidateSafeAction:    candidateAction,
		})
		if err != nil {
			return defenseValidationAPIResponse{}, fmt.Errorf("case %q execution evidence rejected: %w", strings.TrimSpace(raw.CaseRef), err)
		}
		if chainID == 0 {
			chainID = execution.Case.ChainID
		} else if chainID != execution.Case.ChainID {
			return defenseValidationAPIResponse{}, errors.New("all cases in one validation run must use the same chain_id")
		}
		cases = append(cases, execution.Case)

		hasBinding := raw.ObservationBinding != nil
		hasEvent := raw.ObservationEvent != nil
		if hasBinding != hasEvent {
			return defenseValidationAPIResponse{}, fmt.Errorf("case %q must provide observation_binding and observation_event together", strings.TrimSpace(raw.CaseRef))
		}
		if hasBinding {
			observation, err := defense.AdaptSecurityEvidenceObservationV02(control, execution, *raw.ObservationBinding, *raw.ObservationEvent)
			if err != nil {
				return defenseValidationAPIResponse{}, fmt.Errorf("case %q independent observation rejected: %w", strings.TrimSpace(raw.CaseRef), err)
			}
			observations = append(observations, observation)
		}
	}

	report, err := defense.EvaluateDefenseValidationV02(defense.DefenseValidationInputV02{
		RunRef:               input.RunRef,
		Scenario:             scenario,
		ScenarioRef:          scenario.ScenarioRef,
		ScenarioVersion:      scenario.ScenarioVersion,
		ScenarioContractHash: scenarioHash,
		Chain:                scenario.Chain,
		ChainID:              chainID,
		RulesetVersion:       defense.DefenseValidationRulesetVersionV02,
		Controls:             controls,
		Cases:                cases,
		Observations:         observations,
	})
	if err != nil {
		return defenseValidationAPIResponse{}, fmt.Errorf("defense validation report rejected: %w", err)
	}

	return defenseValidationAPIResponse{
		OK:                        true,
		Product:                   "Koschei Defense Validation",
		EvidenceModel:             "recomputed_execution_plus_independent_ed25519_observation",
		ScenarioContractHash:      scenarioHash,
		VerifiedExecutions:        len(cases),
		VerifiedObservations:      len(observations),
		Report:                    report,
		MainnetTransactionSent:    false,
		ExecutionAuthority:        false,
		ProductionControlMutation: false,
		Limitations: []string{
			"This endpoint evaluates evidence from isolated fork/sandbox runs; it does not execute arbitrary payloads or submit mainnet transactions.",
			"A validated report applies only to the exact scenario contract, control configuration, execution receipts and independently signed observations in this run.",
		},
	}, nil
}

func decodeDefenseValidationAPIAction(input defenseValidationAPIAction) (executioncontainment.ActionArtifact, error) {
	kind := strings.TrimSpace(input.Kind)
	encoded := strings.TrimSpace(input.CanonicalBase64)
	if kind == "" || encoded == "" {
		return executioncontainment.ActionArtifact{}, errors.New("kind and canonical_base64 are required")
	}
	canonical, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return executioncontainment.ActionArtifact{}, errors.New("canonical_base64 must use standard base64 encoding")
	}
	if len(canonical) == 0 || len(canonical) > defenseValidationAPIMaxActionBytes {
		return executioncontainment.ActionArtifact{}, fmt.Errorf("decoded action must contain between 1 and %d bytes", defenseValidationAPIMaxActionBytes)
	}
	return executioncontainment.ActionArtifact{Kind: kind, Canonical: canonical}, nil
}
