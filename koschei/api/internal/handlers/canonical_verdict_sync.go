package handlers

import (
	"encoding/json"
	"strconv"
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

	target := strings.TrimSpace(dossierString(report["target"]))
	if target == "" {
		return services.UnifiedRadarVerdict{}, false
	}

	current := services.UnifiedRadarVerdict{}
	if decodeCanonicalVerdictValue(report["final_verdict"], &current) &&
		strings.TrimSpace(current.Signature) != "" && current.Signed &&
		canonicalUnifiedRulesetAtLeast(current.RulesetVersion, 1, 1, 1) {
		normalized := services.FinalizeUnifiedRadarVerdictContract(target, current)
		report["final_verdict"] = normalized
		return normalized, true
	}

	actorSection := canonicalMap(report["actor_investigation"])
	var actor services.ActorDefenseRuleVerdict
	var behavior services.UnifiedRadarBehaviorReport
	if !decodeCanonicalVerdictValue(actorSection["rule_verdict"], &actor) ||
		!decodeCanonicalVerdictValue(report["behavior_signals"], &behavior) {
		return services.UnifiedRadarVerdict{}, false
	}

	var final services.UnifiedRadarVerdict
	if canonicalUnifiedRulesetAtLeast(behavior.RulesetVersion, 1, 2, 0) {
		final = services.EvaluateUnifiedRadarVerdictV120(target, actor, behavior)
	} else {
		final = services.EvaluateUnifiedRadarVerdictV110(target, actor, behavior)
	}
	final = services.FinalizeUnifiedRadarVerdictContract(target, final)
	report["final_verdict"] = final
	return final, true
}

func canonicalUnifiedRulesetAtLeast(version string, major, minor, patch int) bool {
	const prefix = "koschei-unified-radar-rules-v"
	version = strings.TrimSpace(version)
	if !strings.HasPrefix(version, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(version, prefix), ".")
	if len(parts) != 3 {
		return false
	}
	values := make([]int, 3)
	for index, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return false
		}
		values[index] = value
	}
	if values[0] != major {
		return values[0] > major
	}
	if values[1] != minor {
		return values[1] > minor
	}
	return values[2] >= patch
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
