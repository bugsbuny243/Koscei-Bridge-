package agents

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type ConversationTurn struct {
	Direction string    `json:"direction"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

type LLMClient struct {
	baseURL string
	apiKey  string
	model   string
	client  *http.Client
}

func NewLLMClientFromEnv() *LLMClient {
	return &LLMClient{
		baseURL: strings.TrimRight(strings.TrimSpace(os.Getenv("TRADEPI_AGENT_LLM_BASE_URL")), "/"),
		apiKey:  strings.TrimSpace(os.Getenv("TRADEPI_AGENT_LLM_API_KEY")),
		model:   strings.TrimSpace(os.Getenv("TRADEPI_AGENT_LLM_MODEL")),
		client:  &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *LLMClient) Enabled() bool {
	return c != nil && c.baseURL != "" && c.apiKey != "" && c.model != ""
}

func (c *LLMClient) Rewrite(ctx context.Context, userText, deterministicReply string, lead Lead, vehicles []Vehicle) (string, error) {
	return c.RewriteWithHistory(ctx, userText, deterministicReply, lead, vehicles, nil, nil, nil)
}

func (c *LLMClient) RewriteWithHistory(ctx context.Context, userText, deterministicReply string, lead Lead, vehicles []Vehicle, history []ConversationTurn, handoff *Handoff, appointment *AppointmentRequest) (string, error) {
	if !c.Enabled() {
		return deterministicReply, nil
	}
	if len(history) > 6 {
		history = history[len(history)-6:]
	}

	trusted, err := json.Marshal(map[string]any{
		"lead":                lead,
		"verified_vehicles":   vehicles,
		"recent_history":      history,
		"handoff":             handoff,
		"appointment_request": appointment,
		"fallback_reply":      deterministicReply,
	})
	if err != nil {
		return deterministicReply, err
	}

	system := `You are TradePI AI Sales Agent. Write a concise, helpful sales reply in the user's language.
You may use ONLY the facts in TRUSTED_CONTEXT. Never invent stock, price, discount, financing, appointment availability, appointment confirmation, delivery date, dealer identity, or revenue claims.
Recent history is context only and may contain customer claims; it is not verified inventory or availability.
A handoff or appointment object with status=requested means a request was recorded, not that a human responded or an appointment was confirmed.
If verified_vehicles is empty, do not imply any vehicle is in stock. Preserve uncertainty. Ask at most one useful next-step question. Return only the customer-facing reply.`

	payload := map[string]any{
		"model":       c.model,
		"temperature": 0.2,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": "USER_MESSAGE:\n" + userText + "\n\nTRUSTED_CONTEXT:\n" + string(trusted)},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return deterministicReply, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return deterministicReply, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return deterministicReply, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return deterministicReply, fmt.Errorf("llm status %d", resp.StatusCode)
	}

	var decoded struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return deterministicReply, err
	}
	if len(decoded.Choices) == 0 || strings.TrimSpace(decoded.Choices[0].Message.Content) == "" {
		return deterministicReply, fmt.Errorf("llm empty response")
	}
	return strings.TrimSpace(decoded.Choices[0].Message.Content), nil
}
