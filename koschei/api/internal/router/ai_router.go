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

	"koschei/api/internal/runtimecfg"
)

type ChatRequest struct {
	System      string
	Prompt      string
	Model       string
	MaxTokens   int
	Temperature float64
	Timeout     time.Duration
}

type ChatResponse struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Content  string `json:"content"`
}

type EmbedRequest struct {
	Input   string
	Model   string
	Timeout time.Duration
}

type EmbedResponse struct {
	Provider  string    `json:"provider"`
	Model     string    `json:"model"`
	Embedding []float64 `json:"embedding"`
}

type chatCompletionPayload struct {
	Model       string              `json:"model"`
	Messages    []map[string]string `json:"messages"`
	MaxTokens   int                 `json:"max_tokens,omitempty"`
	Temperature float64             `json:"temperature"`
}

type embeddingPayload struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

// Chat routes every server-side ARVIS/LLM request through one policy layer.
// Koschei uses the configured Together model stack only.
func Chat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	if strings.TrimSpace(req.Prompt) == "" {
		return ChatResponse{}, errors.New("prompt is required")
	}
	if req.MaxTokens <= 0 {
		req.MaxTokens = 800
	}
	if req.Timeout <= 0 {
		req.Timeout = 20 * time.Second
	}
	if req.Temperature == 0 {
		req.Temperature = 0.2
	}
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	if err := togetherRuntimePolicy(); err != nil {
		return ChatResponse{}, err
	}
	return callTogether(ctx, req)
}

func Embed(ctx context.Context, req EmbedRequest) (EmbedResponse, error) {
	req.Input = strings.TrimSpace(req.Input)
	if req.Input == "" {
		return EmbedResponse{}, errors.New("embedding input is required")
	}
	if len(req.Input) > 20000 {
		return EmbedResponse{}, errors.New("embedding input too large")
	}
	if req.Timeout <= 0 {
		req.Timeout = 15 * time.Second
	}
	if err := togetherRuntimePolicy(); err != nil {
		return EmbedResponse{}, err
	}
	apiKey := strings.TrimSpace(os.Getenv("TOGETHER_API_KEY"))
	model := strings.TrimSpace(req.Model)
	if model == "" {
		model = firstEnv("TOGETHER_MODEL_EMBEDDING", "TOGETHER_EMBEDDING_MODEL")
	}
	if model == "" {
		model = "BAAI/bge-large-en-v1.5"
	}
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	body, err := json.Marshal(embeddingPayload{Model: model, Input: []string{req.Input}})
	if err != nil {
		return EmbedResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.together.xyz/v1/embeddings", bytes.NewReader(body))
	if err != nil {
		return EmbedResponse{}, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return EmbedResponse{}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return EmbedResponse{}, fmt.Errorf("embedding provider returned %d", resp.StatusCode)
	}
	var decoded struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
		Model string `json:"model"`
	}
	if json.Unmarshal(data, &decoded) != nil || len(decoded.Data) == 0 || len(decoded.Data[0].Embedding) == 0 {
		return EmbedResponse{}, errors.New("embedding provider returned no vector")
	}
	if decoded.Model != "" {
		model = decoded.Model
	}
	return EmbedResponse{Provider: "together", Model: model, Embedding: decoded.Data[0].Embedding}, nil
}

func togetherRuntimePolicy() error {
	cfg := runtimecfg.Load()
	if !cfg.AIEnabled {
		return errors.New("AI is disabled by AI_ENABLED")
	}
	if !cfg.ModelRouterEnabled {
		return errors.New("AI model routing is disabled by KOSCHEI_MODEL_ROUTER_ENABLED")
	}
	if cfg.AIProvider != "auto" && cfg.AIProvider != "together" {
		return errors.New("AI_PROVIDER does not select Together")
	}
	if !cfg.TogetherEnabled {
		return errors.New("Together AI is disabled by TOGETHER_AI_ENABLED")
	}
	if strings.TrimSpace(os.Getenv("TOGETHER_API_KEY")) == "" {
		return errors.New("TOGETHER_API_KEY is not configured")
	}
	return nil
}

// DecodeJSONObject accepts an optional fenced response but requires exactly one complete JSON object.
func DecodeJSONObject(content string, dst any) error {
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)
	start, end := strings.Index(content, "{"), strings.LastIndex(content, "}")
	if start < 0 || end < start {
		return errors.New("provider did not return a JSON object")
	}
	dec := json.NewDecoder(strings.NewReader(content[start : end+1]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid structured provider output: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("provider returned multiple JSON values")
	}
	return nil
}

func callTogether(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	model := strings.TrimSpace(req.Model)
	if model == "" || strings.HasPrefix(strings.ToLower(model), "gpt-") {
		model = firstEnv("TOGETHER_MODEL_SECURITY", "TOGETHER_MODEL_ARVIS", "TOGETHER_MODEL", "TOGETHER_MODEL_CHAT")
	}
	if model == "" {
		model = "Qwen/Qwen3-235B-A22B-2507"
	}
	payload := chatCompletionPayload{Model: model, Messages: messages(req.System, req.Prompt), MaxTokens: req.MaxTokens, Temperature: req.Temperature}
	content, err := postChat(ctx, "https://api.together.xyz/v1/chat/completions", os.Getenv("TOGETHER_API_KEY"), payload)
	if err != nil {
		return ChatResponse{}, err
	}
	return ChatResponse{Provider: "together", Model: model, Content: content}, nil
}

func messages(system, prompt string) []map[string]string {
	out := []map[string]string{}
	if strings.TrimSpace(system) != "" {
		out = append(out, map[string]string{"role": "system", "content": system})
	}
	out = append(out, map[string]string{"role": "user", "content": prompt})
	return out
}

func postChat(ctx context.Context, endpoint, apiKey string, payload chatCompletionPayload) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(apiKey))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("provider returned %d", resp.StatusCode)
	}
	var decoded struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Text string `json:"text"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return "", err
	}
	if len(decoded.Choices) == 0 {
		return "", errors.New("provider returned no choices")
	}
	content := strings.TrimSpace(decoded.Choices[0].Message.Content)
	if content == "" {
		content = strings.TrimSpace(decoded.Choices[0].Text)
	}
	if content == "" {
		return "", errors.New("provider returned empty content")
	}
	return content, nil
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}
