package handlers

import (
	"context"
	"encoding/json"
	"time"

	"koschei/api/internal/defense"
)

func (h *Handler) attachDefenseAgentRuntime(ctx context.Context, report map[string]any, target, network string, now time.Time) defense.RuntimeReport {
	runtime := defense.DisabledReport(target, network, now)
	if !envBool("KOSCHEI_DEFENSE_AGENT_RUNTIME_ENABLED", false) {
		return runtime
	}
	runtime = defense.RunShadow(target, network, defenseRuntimeProjection(report), now)
	if h.DB == nil {
		defense.SetPersistenceStatus(&runtime, "database_unavailable")
	} else {
		defense.AttachArtifactInventory(ctx, h.DB, &runtime)
		if persisted, err := defense.PersistRuntimeReport(ctx, h.DB, runtime); err == nil {
			runtime = persisted
		} else {
			defense.SetPersistenceStatus(&runtime, "persist_failed")
		}
	}
	report["defense_agent_runtime"] = runtime
	policy, ok := report["evidence_policy"].(map[string]any)
	if !ok {
		policy = map[string]any{}
		report["evidence_policy"] = policy
	}
	policy["defense_agent_runtime_can_change_verdict"] = false
	policy["defense_agent_runtime_shadow_only"] = true
	policy["defense_agent_runtime_can_execute_mainnet"] = false
	policy["defense_agent_runtime_can_modify_source"] = false
	return runtime
}

func defenseRuntimeProjection(report map[string]any) map[string]any {
	if report == nil {
		return map[string]any{}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return report
	}
	var normalized map[string]any
	if json.Unmarshal(encoded, &normalized) != nil || normalized == nil {
		return report
	}
	return normalized
}
