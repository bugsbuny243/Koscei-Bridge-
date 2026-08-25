package handlers

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/router"
)

func (h *Handler) ownerChatSpeech(w http.ResponseWriter, r *http.Request, text string) {
	text = normalizeOwnerChatText(text, 2200)
	if text == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "speech_text_required"})
		return
	}
	voice := normalizeOwnerChatText(r.URL.Query().Get("voice"), 80)
	language := strings.ToLower(normalizeOwnerChatText(r.URL.Query().Get("language"), 12))
	if language == "" {
		language = "en"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
	defer cancel()
	result, err := router.Speech(ctx, router.SpeechRequest{
		Input:    text,
		Voice:    voice,
		Language: language,
		Format:   "mp3",
		Timeout:  45 * time.Second,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "owner_social_tts_failed", "detail": shortError(err.Error())})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"mode":         "tts",
		"provider":     result.Provider,
		"model":        result.Model,
		"voice":        result.Voice,
		"format":       result.Format,
		"content_type": result.ContentType,
		"audio_base64": base64.StdEncoding.EncodeToString(result.Audio),
	})
}
