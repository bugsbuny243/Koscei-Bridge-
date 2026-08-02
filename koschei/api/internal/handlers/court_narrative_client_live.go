package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	courtAnthropicVersion = "2023-06-01"
	courtMaxBodyBytes     = 1 << 20
	courtMaxEvidenceBytes = 160 << 10
)

type liveCourtClient struct {
	httpClient *http.Client

	togetherKey  string
	openAIKey    string
	anthropicKey string

	togetherBaseURL  string
	openAIBaseURL    string
	anthropicBaseURL string

	prosecutorLeadModel     string
	prosecutorEvidenceModel string
	panelQwenModel          string
	panelGLMModel           string
	openAIModel             string
	anthropicModel          string

	timeout time.Duration
	retries int
}

type courtModelOutput struct {
	Stance      string   `json:"stance"`
	Opinion     string   `json:"opinion"`
	EvidenceIDs []string `json:"evidence_ids"`
	Limitations []string `json:"limitations"`
}

type courtChatPayload struct {
	Model       string              `json:"model"`
	Messages    []map[string]string `json:"messages"`
	MaxTokens   int                 `json:"max_tokens,omitempty"`
	Temperature float64             `json:"temperature"`
}

type openAIChatPayload struct {
	Model               string              `json:"model"`
	Messages            []map[string]string `json:"messages"`
	MaxCompletionTokens int                 `json:"max_completion_tokens,omitempty"`
}

type openAICompatPayload struct {
	Model     string              `json:"model"`
	Messages  []map[string]string `json:"messages"`
	MaxTokens int                 `json:"max_tokens,omitempty"`
}

type anthropicMessagesPayload struct {
	Model       string                 `json:"model"`
	MaxTokens   int                    `json:"max_tokens"`
	Temperature float64                `json:"temperature,omitempty"`
	System      string                 `json:"system,omitempty"`
	Messages    []anthropicUserMessage `json:"messages"`
}

type anthropicUserMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type courtProviderResult struct {
	opinion CourtOpinion
	err     error
}

// NewCourtNarrativeClientFromEnv activates the lower court only when the
// global court flag and Together credentials are present. Frontier providers
// are optional at construction time; the senior panel reports partial status
// when one of them is unavailable.
func NewCourtNarrativeClientFromEnv() CourtNarrativeClient {
	if !envBool("KOSCHEI_COURT_ENABLED", false) {
		return nil
	}
	togetherKey := strings.TrimSpace(os.Getenv("TOGETHER_API_KEY"))
	if togetherKey == "" {
		return nil
	}
	return &liveCourtClient{
		httpClient:              &http.Client{Timeout: courtEnvDuration("KOSCHEI_COURT_HTTP_TIMEOUT", 75*time.Second)},
		togetherKey:             togetherKey,
		openAIKey:               strings.TrimSpace(os.Getenv("OPENAI_API_KEY")),
		anthropicKey:            strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")),
		togetherBaseURL:         firstNonEmptyString(strings.TrimSpace(os.Getenv("TOGETHER_BASE_URL")), "https://api.together.xyz/v1"),
		openAIBaseURL:           firstNonEmptyString(strings.TrimSpace(os.Getenv("OPENAI_BASE_URL")), "https://api.openai.com/v1"),
		anthropicBaseURL:        firstNonEmptyString(strings.TrimSpace(os.Getenv("ANTHROPIC_BASE_URL")), "https://api.anthropic.com/v1"),
		prosecutorLeadModel:     firstNonEmptyString(strings.TrimSpace(os.Getenv("TOGETHER_MODEL_PROSECUTOR_LEAD")), "moonshotai/Kimi-K2.6"),
		prosecutorEvidenceModel: firstNonEmptyString(strings.TrimSpace(os.Getenv("TOGETHER_MODEL_PROSECUTOR_EVIDENCE")), "MiniMaxAI/MiniMax-M3"),
		panelQwenModel:          firstNonEmptyString(strings.TrimSpace(os.Getenv("TOGETHER_MODEL_TRIBUNAL_QWEN")), strings.TrimSpace(os.Getenv("TOGETHER_MODEL")), "Qwen/Qwen3-235B-A22B-2507"),
		panelGLMModel:           firstNonEmptyString(strings.TrimSpace(os.Getenv("TOGETHER_MODEL_TRIBUNAL_GLM")), "zai-org/GLM-5.2"),
		openAIModel:             strings.TrimSpace(os.Getenv("OPENAI_MODEL_TRIBUNAL")),
		anthropicModel:          strings.TrimSpace(os.Getenv("ANTHROPIC_OWNER_MODEL")),
		timeout:                 courtEnvDuration("KOSCHEI_COURT_MODEL_TIMEOUT", 60*time.Second),
		retries:                 courtEnvInt("KOSCHEI_COURT_PROVIDER_RETRIES", 1, 0, 2),
	}
}

func (c *liveCourtClient) ProsecutorOpinion(ctx context.Context, in CourtReadOnlyInput, role string) (CourtOpinion, error) {
	model := c.prosecutorLeadModel
	roleTitle := "Başsavcı"
	instruction := "Ana iddianameyi hazırla. Suçlayıcı ve aklayıcı delilleri birlikte tart; her açık iddiayı mevcut evidence_id veya rule_id ile bağla."
	if strings.EqualFold(strings.TrimSpace(role), "minimax-m3") {
		model = c.prosecutorEvidenceModel
		roleTitle = "Bağımsız Delil Savcısı"
		instruction = "Dosyayı ana savcıdan bağımsız incele. Kanıt boşluklarını, yanlış-pozitif ihtimallerini ve masum alternatif açıklamaları özellikle ara."
	}
	prompt, err := courtPrompt(in, instruction, nil, nil)
	if err != nil {
		return CourtOpinion{}, err
	}
	out, err := c.callTogether(ctx, model, courtSystemPrompt(roleTitle), prompt, 1700)
	if err != nil {
		return CourtOpinion{}, err
	}
	return courtOpinionFromOutput("together", model, out), nil
}

func (c *liveCourtClient) PanelOpinion(ctx context.Context, in CourtReadOnlyInput, prosecutors []CourtOpinion) (CourtPanel, error) {
	prompt, err := courtPrompt(in,
		"Savcı görüşlerini çapraz sorgula. İddia, çıkarım ve eksik delili ayır. Signed verdict değiştirilemez.",
		prosecutors, nil)
	if err != nil {
		return CourtPanel{}, err
	}
	opinions, providerErrors := c.parallelTogether(ctx, []string{c.panelQwenModel, c.panelGLMModel}, courtSystemPrompt("İlk Derece Mahkemesi Üyesi"), prompt, 1900)
	if len(opinions) == 0 {
		return CourtPanel{}, errors.New("first-instance panel unavailable: " + strings.Join(providerErrors, "; "))
	}
	return CourtPanel{
		Models:      courtOpinionModels(opinions),
		Stance:      presidingCourtStance(in.SignedVerdict.Grade, len(in.SignedVerdict.TriggeredRules) > 0, opinions),
		Text:        courtPanelText("İlk Derece Heyeti", opinions, providerErrors, in),
		Opinions:    opinions,
		Limitations: providerErrors,
	}, nil
}

func (c *liveCourtClient) SeniorOpinion(ctx context.Context, in CourtReadOnlyInput, prosecutors []CourtOpinion, panel *CourtPanel) (CourtPanel, error) {
	prompt, err := courtPrompt(in,
		"Üst heyet incelemesi yap. Çoğunluk görüşünü, varsa muhalefet şerhini, olgu/çıkarım/sınırlama ayrımını ve deterministik exhibit planını açıkla. Yeni delil veya skor üretme.",
		prosecutors, panel)
	if err != nil {
		return CourtPanel{}, err
	}

	type seniorCall struct {
		provider string
		model    string
		call     func(context.Context, string, string, string, int) (courtModelOutput, error)
	}
	calls := []seniorCall{}
	if c.openAIKey != "" && c.openAIModel != "" {
		calls = append(calls, seniorCall{"openai", c.openAIModel, c.callOpenAI})
	}
	if c.anthropicKey != "" && c.anthropicModel != "" {
		calls = append(calls, seniorCall{"anthropic", c.anthropicModel, c.callAnthropic})
	}
	if len(calls) == 0 {
		return CourtPanel{}, errors.New("senior panel requires configured OpenAI or Anthropic model")
	}

	results := make(chan courtProviderResult, len(calls))
	var wg sync.WaitGroup
	for _, item := range calls {
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, callErr := item.call(ctx, item.model, courtSystemPrompt("Üst Heyet Üyesi"), prompt, 2400)
			if callErr != nil {
				results <- courtProviderResult{err: fmt.Errorf("%s/%s: %w", item.provider, item.model, callErr)}
				return
			}
			results <- courtProviderResult{opinion: courtOpinionFromOutput(item.provider, item.model, out)}
		}()
	}
	wg.Wait()
	close(results)

	opinions := []CourtOpinion{}
	providerErrors := []string{}
	for result := range results {
		if result.err != nil {
			providerErrors = append(providerErrors, result.err.Error())
			continue
		}
		opinions = append(opinions, result.opinion)
	}
	if len(opinions) == 0 {
		return CourtPanel{}, errors.New("senior panel unavailable: " + strings.Join(providerErrors, "; "))
	}
	return CourtPanel{
		Models:      courtOpinionModels(opinions),
		Stance:      presidingCourtStance(in.SignedVerdict.Grade, len(in.SignedVerdict.TriggeredRules) > 0, opinions),
		Text:        courtPanelText("Üst Heyet", opinions, providerErrors, in),
		Opinions:    opinions,
		Limitations: providerErrors,
	}, nil
}

func (c *liveCourtClient) parallelTogether(ctx context.Context, models []string, system, prompt string, maxTokens int) ([]CourtOpinion, []string) {
	results := make(chan courtProviderResult, len(models))
	var wg sync.WaitGroup
	for _, model := range models {
		model := strings.TrimSpace(model)
		if model == "" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := c.callTogether(ctx, model, system, prompt, maxTokens)
			if err != nil {
				results <- courtProviderResult{err: fmt.Errorf("%s: %w", model, err)}
				return
			}
			results <- courtProviderResult{opinion: courtOpinionFromOutput("together", model, out)}
		}()
	}
	wg.Wait()
	close(results)

	opinions := []CourtOpinion{}
	providerErrors := []string{}
	for result := range results {
		if result.err != nil {
			providerErrors = append(providerErrors, result.err.Error())
			continue
		}
		opinions = append(opinions, result.opinion)
	}
	return opinions, providerErrors
}

func (c *liveCourtClient) callTogether(ctx context.Context, model, system, prompt string, maxTokens int) (courtModelOutput, error) {
	payload := courtChatPayload{Model: model, Messages: courtMessages(system, prompt), MaxTokens: maxTokens, Temperature: 0.1}
	body, err := json.Marshal(payload)
	if err != nil {
		return courtModelOutput{}, err
	}
	data, err := c.doJSON(ctx, courtEndpoint(c.togetherBaseURL, "chat/completions"), body, map[string]string{
		"Authorization": "Bearer " + c.togetherKey,
		"Content-Type":  "application/json",
	})
	if err != nil {
		return courtModelOutput{}, err
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
		return courtModelOutput{}, err
	}
	if len(decoded.Choices) == 0 {
		return courtModelOutput{}, errors.New("provider returned no choices")
	}
	content := strings.TrimSpace(decoded.Choices[0].Message.Content)
	if content == "" {
		content = strings.TrimSpace(decoded.Choices[0].Text)
	}
	return decodeCourtOutput(content)
}

func (c *liveCourtClient) callOpenAI(ctx context.Context, model, system, prompt string, maxTokens int) (courtModelOutput, error) {
	messages := courtMessages(system, prompt)
	body, err := json.Marshal(openAIChatPayload{Model: model, Messages: messages, MaxCompletionTokens: maxTokens})
	if err != nil {
		return courtModelOutput{}, err
	}
	headers := map[string]string{"Authorization": "Bearer " + c.openAIKey, "Content-Type": "application/json"}
	data, err := c.doJSON(ctx, courtEndpoint(c.openAIBaseURL, "chat/completions"), body, headers)
	if err != nil && strings.Contains(err.Error(), "returned 400") {
		compatBody, marshalErr := json.Marshal(openAICompatPayload{Model: model, Messages: messages, MaxTokens: maxTokens})
		if marshalErr != nil {
			return courtModelOutput{}, marshalErr
		}
		data, err = c.doJSON(ctx, courtEndpoint(c.openAIBaseURL, "chat/completions"), compatBody, headers)
	}
	if err != nil {
		return courtModelOutput{}, err
	}
	var decoded struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return courtModelOutput{}, err
	}
	if len(decoded.Choices) == 0 {
		return courtModelOutput{}, errors.New("OpenAI returned no choices")
	}
	return decodeCourtOutput(decoded.Choices[0].Message.Content)
}

func (c *liveCourtClient) callAnthropic(ctx context.Context, model, system, prompt string, maxTokens int) (courtModelOutput, error) {
	payload := anthropicMessagesPayload{
		Model:       model,
		MaxTokens:   maxTokens,
		Temperature: 0.1,
		System:      system,
		Messages:    []anthropicUserMessage{{Role: "user", Content: prompt}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return courtModelOutput{}, err
	}
	data, err := c.doJSON(ctx, courtEndpoint(c.anthropicBaseURL, "messages"), body, map[string]string{
		"x-api-key":         c.anthropicKey,
		"anthropic-version": courtAnthropicVersion,
		"Content-Type":      "application/json",
	})
	if err != nil {
		return courtModelOutput{}, err
	}
	var decoded struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return courtModelOutput{}, err
	}
	parts := []string{}
	for _, block := range decoded.Content {
		if block.Type == "text" && strings.TrimSpace(block.Text) != "" {
			parts = append(parts, block.Text)
		}
	}
	return decodeCourtOutput(strings.Join(parts, "\n"))
}

func (c *liveCourtClient) doJSON(parent context.Context, endpoint string, body []byte, headers map[string]string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		ctx, cancel := context.WithTimeout(parent, c.timeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			cancel()
			return nil, err
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			if attempt < c.retries {
				time.Sleep(time.Duration(attempt+1) * 250 * time.Millisecond)
				continue
			}
			break
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, courtMaxBodyBytes))
		_ = resp.Body.Close()
		cancel()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return data, nil
		}
		requestID := firstNonEmptyString(resp.Header.Get("x-request-id"), resp.Header.Get("request-id"))
		lastErr = fmt.Errorf("provider returned %d%s: %s", resp.StatusCode, courtRequestIDSuffix(requestID), sanitizeCourtProviderBody(data))
		if attempt < c.retries && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) {
			time.Sleep(time.Duration(attempt+1) * 350 * time.Millisecond)
			continue
		}
		break
	}
	if lastErr == nil {
		lastErr = errors.New("provider request failed")
	}
	return nil, lastErr
}

func courtPrompt(in CourtReadOnlyInput, instruction string, prosecutors []CourtOpinion, panel *CourtPanel) (string, error) {
	packet, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	if len(packet) > courtMaxEvidenceBytes {
		compact := CourtReadOnlyInput{
			Target:         in.Target,
			Network:        in.Network,
			SignedVerdict:  in.SignedVerdict,
			VerdictCard:    in.VerdictCard,
			EvidencePacket: map[string]any{"truncated": true, "reason": "evidence packet exceeded court transport limit"},
		}
		packet, err = json.Marshal(compact)
		if err != nil {
			return "", err
		}
	}
	contextBlock := ""
	if len(prosecutors) > 0 {
		encoded, _ := json.Marshal(prosecutors)
		contextBlock += "\nSAVCI_GORUSLERI:\n" + string(encoded)
	}
	if panel != nil {
		encoded, _ := json.Marshal(panel)
		contextBlock += "\nILK_DERECE_HEYETI:\n" + string(encoded)
	}
	return strings.TrimSpace(instruction) + `

ZORUNLU POLITIKA:
- Sayısal risk skoru veya rug olasılığı üretme.
- Gerçek kişi kimliği veya kötü niyet iddiası kurma.
- Yalnız dosyadaki evidence_id, rule_id, signature ve doğrulanmış alanlara dayan.
- INFERRED veya UNVERIFIED bulguları kesin olguya dönüştürme.
- Signed deterministic verdict nihai otoritedir; grade, verdict ve signature değiştirme.
- Kanıt yetersizse stance="insufficient" kullan.

YALNIZCA SU JSON NESNESINI DON:
{"stance":"elevated|neutral|insufficient","opinion":"gerekceli gorus","evidence_ids":["mevcut id"],"limitations":["sinirlama"]}

DAVA_DOSYASI:
` + string(packet) + contextBlock, nil
}

func courtSystemPrompt(role string) string {
	return "Sen Koschei ARVIS " + role + " rolündesin. Görevin imzalı kanıt dosyasını açıklamak ve çapraz denetlemektir. Yeni kanıt, sayı, kimlik, niyet, grade veya verdict uyduramazsın."
}

func courtMessages(system, prompt string) []map[string]string {
	return []map[string]string{{"role": "system", "content": system}, {"role": "user", "content": prompt}}
}

func decodeCourtOutput(content string) (courtModelOutput, error) {
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start < 0 || end < start {
		return courtModelOutput{}, errors.New("provider did not return JSON court output")
	}
	var out courtModelOutput
	if err := json.Unmarshal([]byte(content[start:end+1]), &out); err != nil {
		return courtModelOutput{}, fmt.Errorf("invalid court JSON: %w", err)
	}
	out.Stance = normalizeCourtStance(out.Stance)
	out.Opinion = strings.TrimSpace(out.Opinion)
	out.EvidenceIDs = courtUniqueStrings(out.EvidenceIDs, 64)
	out.Limitations = courtUniqueStrings(out.Limitations, 32)
	if out.Opinion == "" {
		return courtModelOutput{}, errors.New("court opinion is empty")
	}
	return out, nil
}

func courtOpinionFromOutput(provider, model string, out courtModelOutput) CourtOpinion {
	return CourtOpinion{Provider: provider, Model: model, Stance: out.Stance, Text: out.Opinion, EvidenceIDs: out.EvidenceIDs, Limitations: out.Limitations}
}

func presidingCourtStance(grade string, triggered bool, opinions []CourtOpinion) string {
	if len(opinions) == 0 {
		return "insufficient"
	}
	counts := map[string]int{}
	for _, opinion := range opinions {
		counts[normalizeCourtStance(opinion.Stance)]++
	}
	for _, stance := range []string{"elevated", "neutral", "insufficient"} {
		if counts[stance] > len(opinions)/2 {
			return stance
		}
	}
	if triggered || strings.TrimSpace(grade) != "-" {
		return "elevated"
	}
	return "insufficient"
}

func courtPanelText(title string, opinions []CourtOpinion, providerErrors []string, in CourtReadOnlyInput) string {
	parts := []string{title + ":"}
	for _, opinion := range opinions {
		parts = append(parts, fmt.Sprintf("\n[%s / %s / %s]\n%s", opinion.Provider, opinion.Model, opinion.Stance, opinion.Text))
	}
	if len(providerErrors) > 0 {
		parts = append(parts, "\nProvider sinirlamalari: "+strings.Join(providerErrors, " | "))
	}
	parts = append(parts, "\nARVIS baskanlik kaydi: signed deterministic verdict değişmedi; grade="+strings.TrimSpace(in.SignedVerdict.Grade)+", signature="+strings.TrimSpace(in.SignedVerdict.Signature))
	return strings.Join(parts, "")
}

func courtOpinionModels(opinions []CourtOpinion) []string {
	models := make([]string, 0, len(opinions))
	for _, opinion := range opinions {
		models = append(models, opinion.Model)
	}
	return courtUniqueStrings(models, 16)
}

func normalizeCourtStance(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "elevated":
		return "elevated"
	case "neutral":
		return "neutral"
	default:
		return "insufficient"
	}
}

func courtEndpoint(base, path string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	path = strings.TrimLeft(strings.TrimSpace(path), "/")
	if parsed, err := url.Parse(base); err == nil && parsed.Path != "" && parsed.Path != "/" && strings.HasSuffix(parsed.Path, "/"+path) {
		return base
	}
	return base + "/" + path
}

func courtEnvDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func courtEnvInt(key string, fallback, min, max int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value := 0
	for _, char := range raw {
		if char < '0' || char > '9' {
			return fallback
		}
		value = value*10 + int(char-'0')
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func courtUniqueStrings(values []string, limit int) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func sanitizeCourtProviderBody(data []byte) string {
	text := strings.Join(strings.Fields(string(data)), " ")
	if len(text) > 480 {
		text = text[:480] + "…"
	}
	if text == "" {
		return "empty provider response"
	}
	return text
}

func courtRequestIDSuffix(requestID string) string {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return ""
	}
	return " (request_id=" + requestID + ")"
}
