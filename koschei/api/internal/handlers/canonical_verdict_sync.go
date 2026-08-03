package handlers

import (
	"encoding/json"
	"strings"

	"koschei/api/internal/services"
)

// synchronizeCanonicalUnifiedVerdict runs before immutable report hashing. It
// upgrades an older/stale final-verdict projection from the actor and behavior
// evidence already present in the canonical report. It never starts collectors
// and never invents evidence.
func synchronizeCanonicalUnifiedVerdict(report map[string]any) (services.UnifiedRadarVerdict, bool) {
	if report == nil || isActorDossierReport(report) {
		return services.UnifiedRadarVerdict{}, false
	}

	current := services.UnifiedRadarVerdict{}
	if decodeCanonicalVerdictValue(report["final_verdict"], &current) &&
		current.RulesetVersion == services.UnifiedRadarRulesetVersionV110 &&
		strings.TrimSpace(current.Signature) != "" && current.Signed {
		return current, true
	}

	actorSection := canonicalMap(report["actor_investigation"])
	var actor services.ActorDefenseRuleVerdict
	var behavior services.UnifiedRadarBehaviorReport
	if !decodeCanonicalVerdictValue(actorSection["rule_verdict"], &actor) ||
		!decodeCanonicalVerdictValue(report["behavior_signals"], &behavior) {
		return services.UnifiedRadarVerdict{}, false
	}
	target := strings.TrimSpace(dossierString(report["target"]))
	if target == "" {
		return services.UnifiedRadarVerdict{}, false
	}

	final := services.EvaluateUnifiedRadarVerdictV110(target, actor, behavior)
	report["final_verdict"] = final
	return final, true
}

func decodeCanonicalVerdictValue(raw any, target any) bool {
	if raw == nil || target == nil {
		return false
	}
	encoded, err := json.Marshal(raw)
	if err != nil || len(encoded) == 0 || string(encoded) == "null" {
		return false
	}
	return json.Unmarshal(encoded, target) == nil
}
