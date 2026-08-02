package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestLiveCourtClientDisabledByDefault(t *testing.T) {
	t.Setenv("KOSCHEI_COURT_ENABLED", "false")
	t.Setenv("TOGETHER_API_KEY", "test-key")
	if got := NewCourtNarrativeClientFromEnv(); got != nil {
		t.Fatalf("court client enabled while global flag is false: %#v", got)
	}
}

func TestLiveCourtClientUsesConfiguredModelSeats(t *testing.T) {
	t.Setenv("KOSCHEI_COURT_ENABLED", "true")
	t.Setenv("TOGETHER_API_KEY", "test-key")
	t.Setenv("TOGETHER_MODEL_PROSECUTOR_LEAD", "lead-model")
	t.Setenv("TOGETHER_MODEL_PROSECUTOR_EVIDENCE", "evidence-model")
	t.Setenv("TOGETHER_MODEL_TRIBUNAL_QWEN", "qwen-model")
	t.Setenv("TOGETHER_MODEL_TRIBUNAL_GLM", "glm-model")
	t.Setenv("OPENAI_MODEL_TRIBUNAL", "openai-model")
	t.Setenv("ANTHROPIC_OWNER_MODEL", "anthropic-model")

	client, ok := NewCourtNarrativeClientFromEnv().(*liveCourtClient)
	if !ok || client == nil {
		t.Fatal("live court client was not constructed")
	}
	if client.prosecutorLeadModel != "lead-model" || client.prosecutorEvidenceModel != "evidence-model" {
		t.Fatalf("prosecutor seats=%q/%q", client.prosecutorLeadModel, client.prosecutorEvidenceModel)
	}
	if client.panelQwenModel != "qwen-model" || client.panelGLMModel != "glm-model" {
		t.Fatalf("panel seats=%q/%q", client.panelQwenModel, client.panelGLMModel)
	}
	if client.openAIModel != "openai-model" || client.anthropicModel != "anthropic-model" {
		t.Fatalf("senior seats=%q/%q", client.openAIModel, client.anthropicModel)
	}
}

func TestLiveCourtTogetherOpinionUsesStructuredEvidenceOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Fatalf("path=%q", r.URL.Path)
		}
		var payload courtChatPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if payload.Model != "lead-model" {
			t.Fatalf("model=%q", payload.Model)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"stance\":\"elevated\",\"opinion\":\"Verified rule requires review.\",\"evidence_ids\":[\"RULE-1\"],\"limitations\":[\"bounded window\"]}"}}]}`))
	}))
	defer server.Close()

	client := &liveCourtClient{
		httpClient:              server.Client(),
		togetherKey:             "test-key",
		togetherBaseURL:         server.URL,
		prosecutorLeadModel:     "lead-model",
		prosecutorEvidenceModel: "evidence-model",
		timeout:                 2 * time.Second,
	}
	opinion, err := client.ProsecutorOpinion(context.Background(), testLiveCourtInput(), "kimi-k2.6")
	if err != nil {
		t.Fatalf("opinion error: %v", err)
	}
	if opinion.Provider != "together" || opinion.Model != "lead-model" || opinion.Stance != "elevated" {
		t.Fatalf("opinion=%#v", opinion)
	}
	if len(opinion.EvidenceIDs) != 1 || opinion.EvidenceIDs[0] != "RULE-1" {
		t.Fatalf("evidence=%#v", opinion.EvidenceIDs)
	}
}

func TestPresidingCourtTieCannotEraseDeterministicTrigger(t *testing.T) {
	opinions := []CourtOpinion{{Stance: "neutral"}, {Stance: "insufficient"}}
	if got := presidingCourtStance("D", true, opinions); got != "elevated" {
		t.Fatalf("stance=%q", got)
	}
	if got := presidingCourtStance("-", false, opinions); got != "insufficient" {
		t.Fatalf("no-trigger stance=%q", got)
	}
}

func TestCourtPromptLocksVerdictAndNumericScorePolicy(t *testing.T) {
	prompt, err := courtPrompt(testLiveCourtInput(), "Review the case.", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"Sayısal risk skoru veya rug olasılığı üretme",
		"Signed deterministic verdict nihai otoritedir",
		"grade, verdict ve signature değiştirme",
	} {
		if !strings.Contains(prompt, required) {
			t.Fatalf("prompt missing %q", required)
		}
	}
}

func testLiveCourtInput() CourtReadOnlyInput {
	verdict := services.UnifiedRadarVerdict{
		Grade:          "D",
		Verdict:        "verified_rule_triggered",
		RulesetVersion: services.UnifiedRadarRulesetVersion,
		ActorRuleset:   services.ActorDefenseRulesetVersion,
		Signature:      "signed-case-123456789",
		Signed:         true,
		TriggeredRules: []services.ActorDefenseRuleHit{{RuleID: "RULE-1", EvidenceStatus: "verified"}},
	}
	return CourtReadOnlyInput{
		Target:         "mint",
		Network:        "solana-mainnet",
		SignedVerdict:  verdict,
		VerdictCard:    map[string]any{"grade": verdict.Grade, "signature": verdict.Signature},
		EvidencePacket: map[string]any{"evidence_ids": []string{"RULE-1"}},
	}
}
