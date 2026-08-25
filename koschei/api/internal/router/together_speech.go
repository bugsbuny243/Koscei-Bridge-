package router

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type SpeechRequest struct {
	Input    string
	Model    string
	Voice    string
	Language string
	Format   string
	Timeout  time.Duration
}

type SpeechResponse struct {
	Provider    string
	Model       string
	Voice       string
	Format      string
	ContentType string
	Audio       []byte
}

type togetherSpeechPayload struct {
	Model          string `json:"model"`
	Input          string `json:"input"`
	Voice          string `json:"voice"`
	ResponseFormat string `json:"response_format,omitempty"`
	Language       string `json:"language,omitempty"`
	Stream         bool   `json:"stream"`
}

// Speech generates narration through Together AI. It is server-side only;
// TOGETHER_API_KEY is never exposed to browser code.
func Speech(ctx context.Context, req SpeechRequest) (SpeechResponse, error) {
	input := strings.TrimSpace(req.Input)
	if input == "" {
		return SpeechResponse{}, errors.New("speech input is required")
	}
	if len([]rune(input)) > 2400 {
		return SpeechResponse{}, errors.New("speech input is too large")
	}
	if err := togetherRuntimePolicy(); err != nil {
		return SpeechResponse{}, err
	}
	model := strings.TrimSpace(req.Model)
	if model == "" {
		model = firstEnv("TOGETHER_TTS_MODEL", "TOGETHER_MODEL_TTS")
	}
	if model == "" {
		model = "cartesia/sonic"
	}
	voice := strings.TrimSpace(req.Voice)
	if voice == "" {
		voice = firstEnv("TOGETHER_TTS_VOICE")
	}
	if voice == "" {
		voice = "friendly sidekick"
	}
	language := strings.ToLower(strings.TrimSpace(req.Language))
	if language == "" {
		language = "en"
	}
	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format == "" {
		format = "mp3"
	}
	if format != "mp3" && format != "wav" {
		return SpeechResponse{}, errors.New("speech format must be mp3 or wav")
	}
	if req.Timeout <= 0 {
		req.Timeout = 45 * time.Second
	}

	payload := togetherSpeechPayload{
		Model:          model,
		Input:          input,
		Voice:          voice,
		ResponseFormat: format,
		Language:       language,
		Stream:         false,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return SpeechResponse{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, "https://api.together.ai/v1/audio/speech", bytes.NewReader(body))
	if err != nil {
		return SpeechResponse{}, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(os.Getenv("TOGETHER_API_KEY")))
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return SpeechResponse{}, err
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 12<<20))
	if readErr != nil {
		return SpeechResponse{}, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SpeechResponse{}, fmt.Errorf("speech provider returned %d", resp.StatusCode)
	}
	if len(data) == 0 {
		return SpeechResponse{}, errors.New("speech provider returned empty audio")
	}
	contentType := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if contentType == "" || strings.Contains(contentType, "application/octet-stream") {
		if format == "wav" {
			contentType = "audio/wav"
		} else {
			contentType = "audio/mpeg"
		}
	}
	return SpeechResponse{Provider: "together", Model: model, Voice: voice, Format: format, ContentType: contentType, Audio: data}, nil
}
