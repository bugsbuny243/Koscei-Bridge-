package handlers

import (
	"context"
	"testing"
	"time"

	"koschei/api/internal/defense"
)

type defenseRuntimeLPFixture struct {
	PoolProgram string `json:"pool_program"`
}

func TestAttachDefenseAgentRuntimeIsDisabledByDefault(t *testing.T) {
	t.Setenv("KOSCHEI_DEFENSE_AGENT_RUNTIME_ENABLED", "false")
	report := map[string]any{"evidence_policy": map[string]any{}}
	got := (&Handler{}).attachDefenseAgentRuntime(
		context.Background(), report,
		"Target1111111111111111111111111111111111111", "solana-mainnet",
		time.Date(2026, 7, 19, 5, 0, 0, 0, time.UTC),
	)
	if got.Enabled || got.Status != defense.RuntimeDisabled {
		t.Fatalf("runtime should remain disabled by default: %+v", got)
	}
	if _, exists := report["defense_agent_runtime"]; exists {
		t.Fatalf("disabled runtime mutated the existing Unified Investigation")
	}
	if policy := report["evidence_policy"].(map[string]any); len(policy) != 0 {
		t.Fatalf("disabled runtime changed the legacy evidence policy: %#v", policy)
	}
}

func TestAttachDefenseAgentRuntimeAddsShadowFileWithoutDatabase(t *testing.T) {
	t.Setenv("KOSCHEI_DEFENSE_AGENT_RUNTIME_ENABLED", "true")
	report := map[string]any{
		"evidence_policy": map[string]any{},
		"lp_control": defenseRuntimeLPFixture{
			PoolProgram: "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA",
		},
	}
	got := (&Handler{}).attachDefenseAgentRuntime(
		context.Background(), report,
		"Target1111111111111111111111111111111111111", "solana-mainnet",
		time.Date(2026, 7, 19, 5, 5, 0, 0, time.UTC),
	)
	if !got.Enabled || !got.ShadowMode || got.VerdictAuthority {
		t.Fatalf("shadow runtime was not attached safely: %+v", got)
	}
	if got.Status != defense.RuntimePartial || len(got.EvidenceIDs) == 0 {
		t.Fatalf("typed LP program evidence was not resolved: %+v", got)
	}
	if got.PersistenceStatus != "database_unavailable" {
		t.Fatalf("missing database must be explicit without breaking the report: %+v", got)
	}
	attached, ok := report["defense_agent_runtime"].(defense.RuntimeReport)
	if !ok || attached.CaseRef != got.CaseRef {
		t.Fatalf("runtime report was not attached to Unified Investigation: %#v", report["defense_agent_runtime"])
	}
	policy := report["evidence_policy"].(map[string]any)
	for _, key := range []string{
		"defense_agent_runtime_can_change_verdict",
		"defense_agent_runtime_can_execute_mainnet",
		"defense_agent_runtime_can_modify_source",
	} {
		if value, ok := policy[key].(bool); !ok || value {
			t.Fatalf("fail-closed policy missing for %s: %#v", key, policy[key])
		}
	}
}

func TestDossierSnapshotPathAttachesRuntimeBeforeDatabaseGuard(t *testing.T) {
	t.Setenv("KOSCHEI_DEFENSE_AGENT_RUNTIME_ENABLED", "true")
	report := map[string]any{
		"target":       "Target1111111111111111111111111111111111111",
		"network":      "solana-mainnet",
		"generated_at": "2026-07-19T05:10:00Z",
		"final_verdict": map[string]any{
			"signed": false,
		},
	}
	if err := (&Handler{}).persistDossierSourceSnapshot(context.Background(), report); err != nil {
		t.Fatalf("best-effort snapshot path failed: %v", err)
	}
	if _, ok := report["defense_agent_runtime"].(defense.RuntimeReport); !ok {
		t.Fatalf("runtime was not attached before the database/signed-verdict guard")
	}
}
