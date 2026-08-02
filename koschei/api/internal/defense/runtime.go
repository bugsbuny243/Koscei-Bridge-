package defense

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
)

var solanaAddressLike = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`)

func DisabledReport(target, network string, now time.Time) RuntimeReport {
	now = normalizedTime(now)
	target = strings.TrimSpace(target)
	network = normalizedNetwork(network)
	inputHash := hashValue(map[string]any{"target": target, "network": network, "enabled": false})
	report := RuntimeReport{
		OK:                   true,
		SchemaVersion:        SchemaVersion,
		Enabled:              false,
		ShadowMode:           true,
		ExecutionMode:        ModeDisabled,
		Status:               RuntimeDisabled,
		Target:               target,
		Network:              network,
		GeneratedAt:          now,
		VerdictAuthority:     false,
		CanExecuteMainnet:    false,
		CanModifySource:      false,
		InputHash:            inputHash,
		PersistenceStatus:    "not_requested",
		Agents:               []AgentRun{},
		ToolInvocations:      []ToolInvocation{},
		AvailableTools:       InitialToolRegistry(),
		EvidenceIDs:          []string{},
		Limitations:          []string{"Defense agent runtime is disabled; the existing deterministic investigation remains authoritative."},
		RecommendedNextSteps: []string{"Enable KOSCHEI_DEFENSE_AGENT_RUNTIME_ENABLED only in shadow mode after migration 065 is applied."},
	}
	return finalizeReport(report)
}

// RunShadow builds the first Solana defense-agent file without calling a model,
// executing code, modifying source or sending a transaction. It can only inspect
// evidence already present in the existing Unified Investigation report.
func RunShadow(target, network string, source map[string]any, now time.Time) RuntimeReport {
	now = normalizedTime(now)
	target = strings.TrimSpace(target)
	network = normalizedNetwork(network)
	projection := evidenceProjection(target, network, source)
	inputHash := hashValue(projection)
	programIDs := extractProgramIDs(projection)

	toolInput := map[string]any{
		"target":                 target,
		"network":                network,
		"source_projection_hash": inputHash,
		"allowed_scope":          "existing_unified_investigation_only",
	}
	toolOutput := map[string]any{
		"program_ids":              programIDs,
		"program_count":            len(programIDs),
		"source_artifact_status":   "not_attached",
		"idl_artifact_status":      "not_attached",
		"bytecode_artifact_status": "not_attached",
	}
	toolStatus := ToolObserved
	programStatus := RuntimeObserved
	programLimitations := []string{
		"Program identifiers are resolved only from the existing investigation file.",
		"Source, IDL and sBPF bytecode retrieval are not enabled in runtime v1.",
	}
	if len(programIDs) == 0 {
		toolStatus = ToolEvidencePending
		programStatus = RuntimeEvidencePending
		programLimitations = append(programLimitations, "No program identifier was present in the bounded evidence projection.")
	}
	toolStartedAt := now
	toolFinishedAt := now
	toolInputHash := hashValue(toolInput)
	toolOutputHash := hashValue(toolOutput)
	toolRunID := prefixedID("KTR1-", map[string]any{
		"role": RoleProgramArchaeologist, "tool": "resolve_program_surface",
		"input_hash": toolInputHash, "output_hash": toolOutputHash, "at": now.Format(time.RFC3339Nano),
	})
	evidenceIDs := []string{}
	if len(programIDs) > 0 {
		evidenceIDs = append(evidenceIDs, "defense:program_surface:"+strings.TrimPrefix(toolOutputHash, "sha256:")[:16])
	}
	invocation := ToolInvocation{
		ToolRunID: toolRunID, AgentRole: RoleProgramArchaeologist,
		ToolName: "resolve_program_surface", Status: toolStatus,
		InputHash: toolInputHash, OutputHash: toolOutputHash,
		Input: toolInput, Output: toolOutput,
		EvidenceIDs: evidenceIDs, Limitations: append([]string{}, programLimitations...),
		StartedAt: toolStartedAt, FinishedAt: toolFinishedAt,
	}

	agents := []AgentRun{
		{
			Role: RoleProgramArchaeologist, Status: programStatus,
			Objective:  "Resolve the program surface behind the target and establish which source, IDL or bytecode artifacts are missing.",
			ToolRunIDs: []string{toolRunID}, EvidenceIDs: append([]string{}, evidenceIDs...),
			Limitations: append([]string{}, programLimitations...), VerdictAuthority: false,
		},
		{
			Role: RoleStaticAnalyzer, Status: RuntimeEvidencePending,
			Objective:  "Analyze Solana and Anchor account validation, PDA, CPI, authority and arithmetic surfaces.",
			ToolRunIDs: []string{}, EvidenceIDs: []string{},
			Limitations:      []string{"Static detectors are blocked until a verified source, IDL or bytecode artifact is attached."},
			VerdictAuthority: false,
		},
		{
			Role: RoleReproductionAgent, Status: RuntimeBlocked,
			Objective:  "Prepare a local-SVM reproduction plan for a verified and reachable program-security finding.",
			ToolRunIDs: []string{}, EvidenceIDs: []string{},
			Limitations:      []string{"No verified program-security finding exists yet; reproduction cannot start.", "Mainnet execution is prohibited."},
			VerdictAuthority: false,
		},
	}

	status := RuntimeEvidencePending
	if len(programIDs) > 0 {
		status = RuntimePartial
	}
	report := RuntimeReport{
		OK: true, SchemaVersion: SchemaVersion, Enabled: true, ShadowMode: true,
		ExecutionMode: ModeShadow, Status: status,
		Target: target, Network: network, GeneratedAt: now,
		VerdictAuthority: false, CanExecuteMainnet: false, CanModifySource: false,
		InputHash: inputHash, PersistenceStatus: "pending",
		Agents: agents, ToolInvocations: []ToolInvocation{invocation},
		AvailableTools: InitialToolRegistry(), EvidenceIDs: append([]string{}, evidenceIDs...),
		Limitations: []string{
			"Runtime v1 is shadow-only and cannot alter the signed deterministic verdict.",
			"No model, compiler, fuzzer, sandbox or external artifact source is invoked in this phase.",
			"Observed program identifiers are not vulnerability findings.",
		},
		RecommendedNextSteps: []string{
			"Attach verified source, Anchor IDL or sBPF bytecode artifacts.",
			"Enable the sandboxed instruction-graph and static-detector tools after benchmark gates pass.",
			"Keep program findings observational until reproduction and deterministic acceptance rules exist.",
		},
	}
	return finalizeReport(report)
}

func SetPersistenceStatus(report *RuntimeReport, status string) {
	if report == nil {
		return
	}
	report.PersistenceStatus = strings.TrimSpace(status)
	report.ReportHash = reportHash(*report)
}

func evidenceProjection(target, network string, source map[string]any) map[string]any {
	projection := map[string]any{"target": target, "network": network}
	for _, key := range []string{
		"final_verdict", "source_context", "structural_memory", "lp_control",
		"modules", "evidence_references", "graph", "actor_investigation",
	} {
		if value, ok := source[key]; ok {
			projection[key] = value
		}
	}
	return projection
}

func extractProgramIDs(value any) []string {
	set := map[string]struct{}{}
	var walk func(any, string)
	walk = func(current any, path string) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				nextPath := strings.ToLower(strings.TrimSpace(path + "." + key))
				walk(child, nextPath)
			}
		case []any:
			for _, child := range typed {
				walk(child, path)
			}
		case []map[string]any:
			for _, child := range typed {
				walk(child, path)
			}
		case string:
			candidate := strings.TrimSpace(typed)
			if !solanaAddressLike.MatchString(candidate) {
				return
			}
			if strings.Contains(path, "program") || strings.Contains(path, "loader") {
				set[candidate] = struct{}{}
			}
		}
	}
	walk(value, "")
	out := make([]string, 0, len(set))
	for candidate := range set {
		out = append(out, candidate)
	}
	sort.Strings(out)
	return out
}

func finalizeReport(report RuntimeReport) RuntimeReport {
	if report.Agents == nil {
		report.Agents = []AgentRun{}
	}
	if report.ToolInvocations == nil {
		report.ToolInvocations = []ToolInvocation{}
	}
	if report.AvailableTools == nil {
		report.AvailableTools = []ToolDefinition{}
	}
	if report.EvidenceIDs == nil {
		report.EvidenceIDs = []string{}
	}
	if report.Limitations == nil {
		report.Limitations = []string{}
	}
	if report.RecommendedNextSteps == nil {
		report.RecommendedNextSteps = []string{}
	}
	if report.CaseRef == "" {
		report.CaseRef = prefixedID("KAR1-", map[string]any{
			"target": report.Target, "network": report.Network,
			"input_hash": report.InputHash, "generated_at": report.GeneratedAt.Format(time.RFC3339Nano),
		})
	}
	report.ReportHash = reportHash(report)
	return report
}

func reportHash(report RuntimeReport) string {
	report.ReportHash = ""
	report.PersistenceStatus = ""
	return hashValue(report)
}

func hashValue(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		encoded = []byte("null")
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func prefixedID(prefix string, value any) string {
	return prefix + strings.TrimPrefix(hashValue(value), "sha256:")[:32]
}

func normalizedNetwork(network string) string {
	network = strings.TrimSpace(network)
	if network == "" {
		return "solana-mainnet"
	}
	return network
}

func normalizedTime(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now().UTC()
	}
	return now.UTC()
}
