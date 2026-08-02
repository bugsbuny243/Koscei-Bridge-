package handlers

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

func trimDossier(value string) string  { return strings.TrimSpace(value) }
func lowerDossier(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func dossierMap(value any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if out, ok := value.(map[string]any); ok {
		return out
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return map[string]any{}
	}
	return out
}

func dossierSlice(value any) []any {
	if value == nil {
		return []any{}
	}
	if out, ok := value.([]any); ok {
		return out
	}
	raw, _ := json.Marshal(value)
	var out []any
	_ = json.Unmarshal(raw, &out)
	return out
}

func dossierString(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func dossierBool(value any) bool { out, ok := value.(bool); return ok && out }

func dossierStrings(value any) []string {
	out := []string{}
	switch typed := value.(type) {
	case []string:
		out = append(out, typed...)
	case []any:
		for _, item := range typed {
			out = append(out, dossierString(item))
		}
	}
	return dossierUniqueStrings(out)
}

func dossierInt64s(value any) []int64 {
	out := []int64{}
	for _, item := range dossierSlice(value) {
		switch typed := item.(type) {
		case float64:
			out = append(out, int64(typed))
		case int64:
			out = append(out, typed)
		case json.Number:
			if parsed, err := typed.Int64(); err == nil {
				out = append(out, parsed)
			}
		}
	}
	return dossierUniqueSlots(out)
}

func dossierUniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func dossierUniqueSlots(values []int64) []int64 {
	seen := map[int64]bool{}
	out := []int64{}
	for _, value := range values {
		if value <= 0 || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func dossierParseTime(value string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, strings.TrimSpace(value)); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func dossierFirst(values ...any) any {
	for _, value := range values {
		if value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) == "" {
				continue
			}
		case []any:
			if len(typed) == 0 {
				continue
			}
		case map[string]any:
			if len(typed) == 0 {
				continue
			}
		}
		return value
	}
	return nil
}

func dossierPretty(value any) string {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(raw)
}
