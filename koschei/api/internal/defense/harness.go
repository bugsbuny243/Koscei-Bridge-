package defense

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const HarnessPlanVersion = "v1.0.0"

type HarnessPlanInput struct {
	IDLArtifactRef    string `json:"idl_artifact_ref"`
	SourceArtifactRef string `json:"source_artifact_ref,omitempty"`
}

type HarnessAccount struct {
	Name      string         `json:"name"`
	Path      string         `json:"path"`
	Writable  bool           `json:"writable"`
	Signer    bool           `json:"signer"`
	Optional  bool           `json:"optional"`
	PDA       bool           `json:"pda"`
	Address   string         `json:"address,omitempty"`
	Relations []string       `json:"relations"`
	Raw       map[string]any `json:"raw"`
}

type HarnessArgument struct {
	Name string `json:"name"`
	Type any    `json:"type"`
}

type HarnessInstruction struct {
	Name          string            `json:"name"`
	Discriminator any               `json:"discriminator,omitempty"`
	Accounts      []HarnessAccount  `json:"accounts"`
	Arguments     []HarnessArgument `json:"arguments"`
	Guidance      []string          `json:"guidance"`
}

type HarnessInvariantTemplate struct {
	TemplateID                string   `json:"template_id"`
	Kind                      string   `json:"kind"`
	Instruction               string   `json:"instruction"`
	Accounts                  []string `json:"accounts"`
	Description               string   `json:"description"`
	HumanConfirmationRequired bool     `json:"human_confirmation_required"`
}

type HarnessEngineCandidate struct {
	Name                   string   `json:"name"`
	Role                   string   `json:"role"`
	Status                 string   `json:"status"`
	RequiredTools          []string `json:"required_tools"`
	ManualGuidanceRequired bool     `json:"manual_guidance_required"`
}

type HarnessPlan struct {
	PlanRef                string                     `json:"plan_ref"`
	PlanVersion            string                     `json:"plan_version"`
	ProgramID              string                     `json:"program_id"`
	Network                string                     `json:"network"`
	IDLArtifactRef         string                     `json:"idl_artifact_ref"`
	SourceArtifactRef      string                     `json:"source_artifact_ref,omitempty"`
	Framework              string                     `json:"framework"`
	FrameworkVersion       string                     `json:"framework_version,omitempty"`
	Instructions           []HarnessInstruction       `json:"instructions"`
	InvariantTemplates     []HarnessInvariantTemplate `json:"invariant_templates"`
	EngineCandidates       []HarnessEngineCandidate   `json:"engine_candidates"`
	InstructionCount       int                        `json:"instruction_count"`
	AccountCount           int                        `json:"account_count"`
	ExecutionReady         bool                       `json:"execution_ready"`
	ManualGuidanceRequired bool                       `json:"manual_guidance_required"`
	EvidenceRefs           []string                   `json:"evidence_refs"`
	Limitations            []string                   `json:"limitations"`
	PlanHash               string                     `json:"plan_hash"`
	VerdictAuthority       bool                       `json:"verdict_authority"`
	CreatedAt              time.Time                  `json:"created_at"`
}

type ToolchainAttestation struct {
	AttestationRef   string    `json:"attestation_ref"`
	WorkerID         string    `json:"worker_id"`
	ToolName         string    `json:"tool_name"`
	Command          string    `json:"command"`
	Available        bool      `json:"available"`
	VersionOutput    string    `json:"version_output"`
	VersionHash      string    `json:"version_hash"`
	EvidenceStatus   string    `json:"evidence_status"`
	Limitations      []string  `json:"limitations"`
	AttestationHash  string    `json:"attestation_hash"`
	VerdictAuthority bool      `json:"verdict_authority"`
	ObservedAt       time.Time `json:"observed_at"`
}

func GenerateHarnessPlan(ctx context.Context, db *sql.DB, input HarnessPlanInput) (HarnessPlan, error) {
	if db == nil {
		return HarnessPlan{}, errors.New("database unavailable")
	}
	input.IDLArtifactRef = strings.TrimSpace(input.IDLArtifactRef)
	input.SourceArtifactRef = strings.TrimSpace(input.SourceArtifactRef)
	if input.IDLArtifactRef == "" {
		return HarnessPlan{}, errors.New("idl_artifact_ref is required")
	}
	idl, err := LoadArtifact(ctx, db, input.IDLArtifactRef)
	if err != nil {
		return HarnessPlan{}, errors.New("IDL artifact not found")
	}
	if idl.ArtifactType != "anchor_idl" {
		return HarnessPlan{}, errors.New("harness planning requires an anchor_idl artifact")
	}
	if input.SourceArtifactRef != "" {
		source, err := LoadArtifact(ctx, db, input.SourceArtifactRef)
		if err != nil {
			return HarnessPlan{}, errors.New("source artifact not found")
		}
		if source.ProgramID != idl.ProgramID || source.Network != idl.Network ||
			(source.ArtifactType != "source_bundle" && source.ArtifactType != "source_manifest") {
			return HarnessPlan{}, errors.New("source artifact does not match the IDL program")
		}
	}
	instructions, accountCount, err := parseAnchorIDLForHarness(idl.Content)
	if err != nil {
		return HarnessPlan{}, err
	}
	templates := buildHarnessInvariantTemplates(instructions)
	engines := []HarnessEngineCandidate{
		{Name: "litesvm", Role: "deterministic_local_svm", Status: "candidate", RequiredTools: []string{"cargo", "rustc"}, ManualGuidanceRequired: true},
		{Name: "trident", Role: "stateful_fuzzing", Status: "candidate", RequiredTools: []string{"cargo", "rustc", "trident"}, ManualGuidanceRequired: true},
	}
	evidence := []string{"artifact:" + idl.ArtifactRef}
	if input.SourceArtifactRef != "" {
		evidence = append(evidence, "artifact:"+input.SourceArtifactRef)
	}
	limitations := []string{
		"IDL exposes instruction, argument and account metadata but does not fully specify account initialization, economic invariants or valid adversarial sequences.",
		"Generated invariant templates require human confirmation before they can become a versioned reproduction invariant.",
		"This plan does not execute source code, generate an exploit claim or establish reachability.",
	}
	payload := map[string]any{
		"schema_version":           "koschei-anchor-harness-plan-v1",
		"plan_version":             HarnessPlanVersion,
		"program_id":               idl.ProgramID,
		"network":                  idl.Network,
		"idl_artifact_ref":         idl.ArtifactRef,
		"source_artifact_ref":      input.SourceArtifactRef,
		"instructions":             instructions,
		"invariant_templates":      templates,
		"engine_candidates":        engines,
		"execution_ready":          false,
		"manual_guidance_required": true,
	}
	planHash := hashJSON(payload)
	planRef := prefixedID("KHP1-", payload)
	now := time.Now().UTC()
	plan := HarnessPlan{PlanRef: planRef, PlanVersion: HarnessPlanVersion, ProgramID: idl.ProgramID, Network: idl.Network,
		IDLArtifactRef: idl.ArtifactRef, SourceArtifactRef: input.SourceArtifactRef, Framework: "anchor",
		FrameworkVersion: idl.FrameworkVersion, Instructions: instructions, InvariantTemplates: templates, EngineCandidates: engines,
		InstructionCount: len(instructions), AccountCount: accountCount, ExecutionReady: false, ManualGuidanceRequired: true,
		EvidenceRefs: uniqueStrings(evidence), Limitations: limitations, PlanHash: planHash, VerdictAuthority: false, CreatedAt: now}
	planRaw, _ := json.Marshal(payload)
	enginesRaw, _ := json.Marshal(engines)
	evidenceRaw, _ := json.Marshal(plan.EvidenceRefs)
	limitationsRaw, _ := json.Marshal(plan.Limitations)
	_, err = db.ExecContext(ctx, `INSERT INTO defense_harness_plans
		(plan_ref,plan_version,program_id,network,idl_artifact_ref,source_artifact_ref,framework,framework_version,instruction_count,account_count,
		 engine_candidates,plan_json,plan_hash,execution_ready,manual_guidance_required,evidence_refs,limitations,verdict_authority,created_by,created_at)
		VALUES($1,$2,$3,$4,$5,NULLIF($6,''),'anchor',NULLIF($7,''),$8,$9,$10::jsonb,$11::jsonb,$12,false,true,$13::jsonb,$14::jsonb,false,'owner',$15)
		ON CONFLICT(plan_ref) DO NOTHING`, plan.PlanRef, plan.PlanVersion, plan.ProgramID, plan.Network, plan.IDLArtifactRef,
		plan.SourceArtifactRef, plan.FrameworkVersion, plan.InstructionCount, plan.AccountCount, string(enginesRaw), string(planRaw),
		plan.PlanHash, string(evidenceRaw), string(limitationsRaw), plan.CreatedAt)
	if err != nil {
		return HarnessPlan{}, err
	}
	return plan, nil
}

func parseAnchorIDLForHarness(content []byte) ([]HarnessInstruction, int, error) {
	var root map[string]any
	if err := json.Unmarshal(content, &root); err != nil {
		return nil, 0, errors.New("Anchor IDL is not valid JSON")
	}
	rawInstructions, ok := root["instructions"].([]any)
	if !ok || len(rawInstructions) == 0 {
		return nil, 0, errors.New("Anchor IDL contains no instructions")
	}
	instructions := []HarnessInstruction{}
	accountCount := 0
	for _, raw := range rawInstructions {
		object, _ := raw.(map[string]any)
		name := strings.TrimSpace(fmt.Sprint(object["name"]))
		if name == "" {
			continue
		}
		accounts := []HarnessAccount{}
		if rawAccounts, ok := object["accounts"].([]any); ok {
			accounts = flattenHarnessAccounts(rawAccounts, "")
		}
		arguments := []HarnessArgument{}
		if rawArgs, ok := object["args"].([]any); ok {
			for _, rawArg := range rawArgs {
				arg, _ := rawArg.(map[string]any)
				argName := strings.TrimSpace(fmt.Sprint(arg["name"]))
				if argName == "" {
					continue
				}
				arguments = append(arguments, HarnessArgument{Name: argName, Type: arg["type"]})
			}
		}
		guidance := []string{"Provide valid account fixtures and instruction arguments before execution."}
		if len(accounts) == 0 {
			guidance = append(guidance, "IDL supplied no account metadata for this instruction.")
		}
		instructions = append(instructions, HarnessInstruction{Name: name, Discriminator: object["discriminator"], Accounts: accounts,
			Arguments: arguments, Guidance: guidance})
		accountCount += len(accounts)
	}
	if len(instructions) == 0 {
		return nil, 0, errors.New("Anchor IDL contains no named instructions")
	}
	sort.Slice(instructions, func(i, j int) bool { return instructions[i].Name < instructions[j].Name })
	return instructions, accountCount, nil
}

func flattenHarnessAccounts(raw []any, prefix string) []HarnessAccount {
	out := []HarnessAccount{}
	for _, item := range raw {
		object, _ := item.(map[string]any)
		name := strings.TrimSpace(fmt.Sprint(object["name"]))
		if name == "" {
			continue
		}
		pathName := name
		if prefix != "" {
			pathName = prefix + "." + name
		}
		if nested, ok := object["accounts"].([]any); ok && len(nested) > 0 {
			out = append(out, flattenHarnessAccounts(nested, pathName)...)
			continue
		}
		writable := boolField(object, "writable") || boolField(object, "isMut")
		signer := boolField(object, "signer") || boolField(object, "isSigner")
		optional := boolField(object, "optional") || boolField(object, "isOptional")
		_, hasPDA := object["pda"]
		address := strings.TrimSpace(fmt.Sprint(object["address"]))
		if address == "<nil>" {
			address = ""
		}
		relations := stringSlice(object["relations"])
		out = append(out, HarnessAccount{Name: name, Path: pathName, Writable: writable, Signer: signer, Optional: optional,
			PDA: hasPDA, Address: address, Relations: relations, Raw: object})
	}
	return out
}

func boolField(object map[string]any, key string) bool {
	value, ok := object[key]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return false
	}
}

func buildHarnessInvariantTemplates(instructions []HarnessInstruction) []HarnessInvariantTemplate {
	out := []HarnessInvariantTemplate{}
	for _, instruction := range instructions {
		out = append(out, HarnessInvariantTemplate{TemplateID: "KHT-NO-PANIC:" + instruction.Name, Kind: "instruction_no_unexpected_panic",
			Instruction: instruction.Name, Accounts: []string{}, Description: "Instruction should not panic for inputs accepted by the confirmed harness grammar.", HumanConfirmationRequired: true})
		signers, readOnly, writable := []string{}, []string{}, []string{}
		for _, account := range instruction.Accounts {
			if account.Signer {
				signers = append(signers, account.Path)
			}
			if account.Writable {
				writable = append(writable, account.Path)
			} else {
				readOnly = append(readOnly, account.Path)
			}
		}
		if len(signers) > 0 {
			out = append(out, HarnessInvariantTemplate{TemplateID: "KHT-SIGNER:" + instruction.Name, Kind: "signer_authorization_template",
				Instruction: instruction.Name, Accounts: signers, Description: "Confirm which signer substitutions must be rejected and encode them as adversarial cases.", HumanConfirmationRequired: true})
		}
		if len(readOnly) > 0 {
			out = append(out, HarnessInvariantTemplate{TemplateID: "KHT-READONLY:" + instruction.Name, Kind: "readonly_account_unchanged_template",
				Instruction: instruction.Name, Accounts: readOnly, Description: "Confirm which read-only accounts must remain byte-identical across the instruction.", HumanConfirmationRequired: true})
		}
		if len(writable) > 0 {
			out = append(out, HarnessInvariantTemplate{TemplateID: "KHT-WRITABLE:" + instruction.Name, Kind: "writable_state_transition_template",
				Instruction: instruction.Name, Accounts: writable, Description: "Define allowed state transitions and economic conservation rules for writable accounts.", HumanConfirmationRequired: true})
		}
	}
	return out
}

func ListHarnessPlans(ctx context.Context, db *sql.DB, programID string, limit int) ([]HarnessPlan, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.QueryContext(ctx, `SELECT plan_ref,plan_version,program_id,network,idl_artifact_ref,COALESCE(source_artifact_ref,''),framework,
		COALESCE(framework_version,''),instruction_count,account_count,plan_json,plan_hash,execution_ready,manual_guidance_required,
		evidence_refs,limitations,verdict_authority,created_at FROM defense_harness_plans
		WHERE ($1='' OR program_id=$1) ORDER BY created_at DESC LIMIT $2`, strings.TrimSpace(programID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HarnessPlan{}
	for rows.Next() {
		var item HarnessPlan
		var planRaw, evidenceRaw, limitationsRaw []byte
		if err := rows.Scan(&item.PlanRef, &item.PlanVersion, &item.ProgramID, &item.Network, &item.IDLArtifactRef, &item.SourceArtifactRef,
			&item.Framework, &item.FrameworkVersion, &item.InstructionCount, &item.AccountCount, &planRaw, &item.PlanHash,
			&item.ExecutionReady, &item.ManualGuidanceRequired, &evidenceRaw, &limitationsRaw, &item.VerdictAuthority, &item.CreatedAt); err != nil {
			return nil, err
		}
		var payload struct {
			Instructions       []HarnessInstruction       `json:"instructions"`
			InvariantTemplates []HarnessInvariantTemplate `json:"invariant_templates"`
			EngineCandidates   []HarnessEngineCandidate   `json:"engine_candidates"`
		}
		_ = json.Unmarshal(planRaw, &payload)
		item.Instructions, item.InvariantTemplates, item.EngineCandidates = payload.Instructions, payload.InvariantTemplates, payload.EngineCandidates
		_ = json.Unmarshal(evidenceRaw, &item.EvidenceRefs)
		_ = json.Unmarshal(limitationsRaw, &item.Limitations)
		out = append(out, item)
	}
	return out, rows.Err()
}

func AttestLocalToolchain(ctx context.Context, db *sql.DB, workerID string) ([]ToolchainAttestation, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return nil, errors.New("worker_id is required")
	}
	commands := []struct {
		Name string
		Args []string
	}{
		{Name: "rustc", Args: []string{"rustc", "--version"}},
		{Name: "cargo", Args: []string{"cargo", "--version"}},
		{Name: "solana", Args: []string{"solana", "--version"}},
		{Name: "anchor", Args: []string{"anchor", "--version"}},
		{Name: "trident", Args: []string{"trident", "--version"}},
	}
	out := []ToolchainAttestation{}
	for _, spec := range commands {
		observedAt := time.Now().UTC()
		probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		cmd := exec.CommandContext(probeCtx, spec.Args[0], spec.Args[1:]...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=/tmp"}
		data, err := cmd.CombinedOutput()
		cancel()
		version := strings.TrimSpace(string(data))
		if len(version) > 2000 {
			version = version[:2000]
		}
		available := err == nil && version != ""
		status := "observed"
		limitations := []string{}
		if !available {
			status = "unavailable"
			limitations = append(limitations, "Tool was not available or did not return a successful version response in this worker image.")
			if version == "" && err != nil {
				version = err.Error()
			}
		}
		versionHash := hashValue(version)
		payload := map[string]any{"worker_id": workerID, "tool_name": spec.Name, "command": strings.Join(spec.Args, " "),
			"available": available, "version_hash": versionHash, "observed_at": observedAt.Format(time.RFC3339Nano)}
		attestationHash := hashJSON(payload)
		ref := prefixedID("KTA1-", payload)
		limitationsRaw, _ := json.Marshal(limitations)
		_, persistErr := db.ExecContext(ctx, `INSERT INTO defense_toolchain_attestations
			(attestation_ref,worker_id,tool_name,command,available,version_output,version_hash,evidence_status,limitations,attestation_hash,verdict_authority,observed_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,false,$11)`, ref, workerID, spec.Name, strings.Join(spec.Args, " "),
			available, version, versionHash, status, string(limitationsRaw), attestationHash, observedAt)
		if persistErr != nil {
			return nil, persistErr
		}
		out = append(out, ToolchainAttestation{AttestationRef: ref, WorkerID: workerID, ToolName: spec.Name, Command: strings.Join(spec.Args, " "),
			Available: available, VersionOutput: version, VersionHash: versionHash, EvidenceStatus: status, Limitations: limitations,
			AttestationHash: attestationHash, VerdictAuthority: false, ObservedAt: observedAt})
	}
	return out, nil
}

func ListToolchainAttestations(ctx context.Context, db *sql.DB, workerID string, limit int) ([]ToolchainAttestation, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.QueryContext(ctx, `SELECT attestation_ref,worker_id,tool_name,command,available,version_output,version_hash,
		evidence_status,limitations,attestation_hash,verdict_authority,observed_at FROM defense_toolchain_attestations
		WHERE ($1='' OR worker_id=$1) ORDER BY observed_at DESC LIMIT $2`, strings.TrimSpace(workerID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ToolchainAttestation{}
	for rows.Next() {
		var item ToolchainAttestation
		var limitationsRaw []byte
		if err := rows.Scan(&item.AttestationRef, &item.WorkerID, &item.ToolName, &item.Command, &item.Available,
			&item.VersionOutput, &item.VersionHash, &item.EvidenceStatus, &limitationsRaw, &item.AttestationHash,
			&item.VerdictAuthority, &item.ObservedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(limitationsRaw, &item.Limitations)
		out = append(out, item)
	}
	return out, rows.Err()
}
