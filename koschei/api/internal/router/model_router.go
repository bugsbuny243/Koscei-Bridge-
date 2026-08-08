package router

import (
	"os"
	"strings"

	"koschei/api/internal/runtimecfg"
)

type ModelRoute struct {
	Route    string `json:"route"`
	Provider string `json:"provider"`
	Status   string `json:"status"`
	Message  string `json:"message"`
}

const (
	liveStatus         = "live"
	disabledStatus     = "disabled"
	unconfiguredStatus = "unconfigured"
)

var toolRouteMap = map[string]string{
	"code-generator":  "code_generation",
	"debug":           "code_debug",
	"refactor":        "code_refactor",
	"analysis":        "chat_analysis",
	"strategy":        "deep_reasoning",
	"image-studio":    "image_generation",
	"image-edit":      "image_editing",
	"video-studio":    "video_generation",
	"cinematic-video": "cinematic_video",
	"voice-lab":       "text_to_speech",
	"speech-to-text":  "speech_to_text",
}

func ResolveModelRoute(tool string) ModelRoute {
	route := toolRouteMap[strings.TrimSpace(strings.ToLower(tool))]
	if route == "" {
		route = "chat_analysis"
	}
	provider := providerFromEnv()
	model := defaultModel(provider)
	status := liveStatus
	message := "Live provider route selected."
	if provider == "disabled" {
		status = disabledStatus
		message = "AI model routing is disabled by runtime policy."
	} else if provider == "unconfigured" {
		status = unconfiguredStatus
		message = "No enabled AI provider is configured."
	}
	return ModelRoute{Route: model, Provider: provider, Status: status, Message: message}
}

func providerFromEnv() string {
	cfg := runtimecfg.LoadWith(getEnv)
	if !cfg.AIEnabled || !cfg.ModelRouterEnabled {
		return "disabled"
	}
	requested := cfg.AIProvider
	if requested == "auto" || requested == "together" {
		if cfg.TogetherEnabled && strings.TrimSpace(getEnv("TOGETHER_API_KEY")) != "" {
			return "together"
		}
	}
	return "unconfigured"
}

func defaultModel(provider string) string {
	switch provider {
	case "together":
		return firstNonEmptyEnv("TOGETHER_MODEL", "TOGETHER_MODEL_CHAT", "meta-llama/Llama-3.3-70B-Instruct-Turbo")
	default:
		return "unconfigured"
	}
}

var getEnv = os.Getenv

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if strings.HasPrefix(key, "TOGETHER_") {
			if value := strings.TrimSpace(getEnv(key)); value != "" {
				return value
			}
			continue
		}
		if strings.TrimSpace(key) != "" {
			return key
		}
	}
	return ""
}
