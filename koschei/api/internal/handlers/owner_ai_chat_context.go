package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const ownerChatSystemPrompt = `You are Koschei Owner Copilot, the private operational assistant inside the Koschei Web3 owner panel.

Rules:
- Answer in Turkish unless the owner explicitly asks for another language.
- Speak naturally, directly and conversationally. Be concise, but explain important risks.
- Use the supplied operational snapshot and deterministic Radar result as the source of truth.
- Koschei uses a free-core + SaaS entitlement access model. Starter, Professional and Enterprise plans authorize paid product surfaces.
- Paddle is the billing provider for SaaS entitlements. Wallet verification is identity-only and KOSCH holdings grant no plan, quota, evidence, security or verdict authority.
- Clearly distinguish verified facts, estimates and suggestions.
- Never claim that an action was executed unless the snapshot or deterministic result proves it.
- Never reveal, reconstruct or request API keys, private keys, tokens, passwords, database URLs or service-account secrets.
- This chat is operationally read-only. The separate owner Radar scanner may perform a read-only scan and persist its signed evidence record.
- Treat Koschei as production-grade Solana security and risk intelligence infrastructure, not a demo.
- Auth is frozen and must not be changed unless the owner explicitly removes that restriction.
- A creator/deployer wallet, holder concentration or linked-wallet signal is evidence of an on-chain relation, not proof of fraud or a real-world identity.
- When data is unavailable, say so instead of inventing it.
- Do not output raw JSON unless the owner asks for it. Summarize data in human language.`

type ownerChatSnapshot struct {
	GeneratedAt string         `json:"generated_at"`
	Services    map[string]any `json:"services"`
	Business    map[string]any `json:"business"`
	Access      map[string]any `json:"access"`
	Radar       map[string]any `json:"radar"`
}

func (h *Handler) buildOwnerChatSnapshot(ctx context.Context) ownerChatSnapshot {
	snapshot := ownerChatSnapshot{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Services: map[string]any{
			"database":        ownerDatabaseStatus(ctx, h.DB),
			"ai_provider":     ownerAIProviderStatus(),
			"neon_auth":       configuredStatus("NEON_AUTH_JWKS_URL"),
			"solana_rpc":      configuredStatusAny("SOLANA_RPC_URL", "ALCHEMY_SOLANA_RPC_URL", "HELIUS_SOLANA_RPC_URL", "QUICKNODE_SOLANA_RPC_URL", "ALCHEMY_API_KEY"),
			"saas_billing":    serviceStatus(strings.TrimSpace(os.Getenv("PADDLE_API_KEY")) != "" && strings.TrimSpace(os.Getenv("PADDLE_WEBHOOK_SECRET")) != "", "configured", "missing"),
			"visual_renderer": "client_canvas_png_ready",
		},
		Business: map[string]any{},
		Access: map[string]any{
			"model":             "free_core_saas_entitlement",
			"free_core":         []string{"safe_check", "basic_token_scan"},
			"paid_plans":        []string{"starter", "professional", "enterprise"},
			"payment_providers": []string{"paddle"},
			"kosch_mint":        configuredKoscheiTokenMint(),
			"kosch_authority":   "none",
		},
		Radar: map[string]any{},
	}

	if ownerTableExists(ctx, h.DB, "app_user_profiles") {
		snapshot.Business["total_users"] = ownerCount(ctx, h.DB, `SELECT count(*) FROM app_user_profiles`)
		snapshot.Business["active_users"] = ownerCount(ctx, h.DB, `SELECT count(*) FROM app_user_profiles WHERE COALESCE(status,'active')='active'`)
	}
	if ownerTableExists(ctx, h.DB, "verified_wallet_links") {
		snapshot.Access["verified_wallets"] = ownerCount(ctx, h.DB, `SELECT count(DISTINCT auth_subject) FROM verified_wallet_links WHERE status='active'`)
	}
	if ownerTableExists(ctx, h.DB, "entitlements") {
		active := `WITH active AS (
			SELECT CASE lower(COALESCE(plan_id,''))
			  WHEN 'basic' THEN 'starter' WHEN 'pro' THEN 'professional'
			  WHEN 'builder' THEN 'professional' WHEN 'studio' THEN 'enterprise'
			  ELSE lower(COALESCE(plan_id,'')) END AS plan
			FROM entitlements
			WHERE status='active' AND COALESCE(plan_id,'')<>'' AND COALESCE(plan_id,'')<>'free'
			  AND (expires_at IS NULL OR expires_at>now())
		)`
		snapshot.Access["active_saas_entitlements"] = ownerCount(ctx, h.DB, active+` SELECT count(*) FROM active WHERE plan IN ('starter','professional','enterprise')`)
		snapshot.Access["starter"] = ownerCount(ctx, h.DB, active+` SELECT count(*) FROM active WHERE plan='starter'`)
		snapshot.Access["professional"] = ownerCount(ctx, h.DB, active+` SELECT count(*) FROM active WHERE plan='professional'`)
		snapshot.Access["enterprise"] = ownerCount(ctx, h.DB, active+` SELECT count(*) FROM active WHERE plan='enterprise'`)
	}
	if ownerTableExists(ctx, h.DB, "customer_feedback") {
		snapshot.Business["open_feedback"] = ownerCount(ctx, h.DB, `SELECT count(*) FROM customer_feedback WHERE status IN ('new','reviewing','planned')`)
		snapshot.Business["security_feedback"] = ownerCount(ctx, h.DB, `SELECT count(*) FROM customer_feedback WHERE category='security' AND status IN ('new','reviewing')`)
	}
	if ownerTableExists(ctx, h.DB, "security_audit_events") {
		snapshot.Business["security_events_24h"] = ownerCount(ctx, h.DB, `SELECT count(*) FROM security_audit_events WHERE created_at>=now()-interval '24 hours'`)
		snapshot.Business["critical_security_events_24h"] = ownerCount(ctx, h.DB, `SELECT count(*) FROM security_audit_events WHERE created_at>=now()-interval '24 hours' AND lower(COALESCE(severity,'')) IN ('critical','fatal','high','error')`)
	}
	if ownerTableExists(ctx, h.DB, "arvis_stream_processing") {
		snapshot.Radar["completed"] = ownerCount(ctx, h.DB, `SELECT count(*) FROM arvis_stream_processing WHERE status='completed'`)
		snapshot.Radar["processing"] = ownerCount(ctx, h.DB, `SELECT count(*) FROM arvis_stream_processing WHERE status='processing'`)
		snapshot.Radar["retryable"] = ownerCount(ctx, h.DB, `SELECT count(*) FROM arvis_stream_processing WHERE status='failed' AND attempts<3`)
		snapshot.Radar["exhausted"] = ownerCount(ctx, h.DB, `SELECT count(*) FROM arvis_stream_processing WHERE status='exhausted' OR (status='failed' AND attempts>=3)`)
	}
	if ownerTableExists(ctx, h.DB, "security_radar_events") {
		snapshot.Radar["events_total"] = ownerCount(ctx, h.DB, `SELECT count(*) FROM security_radar_events`)
		snapshot.Radar["latest_pump_event"] = ownerTimestamp(ctx, h.DB, `SELECT max(created_at) FROM security_radar_events WHERE module_id='pump_sybil_radar'`)
		snapshot.Radar["latest_raydium_event"] = ownerTimestamp(ctx, h.DB, `SELECT max(created_at) FROM security_radar_events WHERE module_id='raydium_pool_guardian'`)
	}
	if ownerTableExists(ctx, h.DB, "security_radar_verdicts") {
		snapshot.Radar["verdicts_total"] = ownerCount(ctx, h.DB, `SELECT count(*) FROM security_radar_verdicts`)
		snapshot.Radar["final_verdicts_24h"] = ownerCount(ctx, h.DB, `SELECT count(*) FROM security_radar_verdicts WHERE module_id='final_verdict_engine' AND signed=true AND created_at>=now()-interval '24 hours'`)
		snapshot.Radar["high_risk_24h"] = ownerCount(ctx, h.DB, `SELECT count(*) FROM security_radar_verdicts WHERE module_id='final_verdict_engine' AND signed=true AND created_at>=now()-interval '24 hours' AND lower(COALESCE(risk_level,'')) IN ('high','critical')`)
		snapshot.Radar["latest_final_verdict"] = ownerTimestamp(ctx, h.DB, `SELECT max(created_at) FROM security_radar_verdicts WHERE module_id='final_verdict_engine'`)
	}
	return snapshot
}

func ownerDatabaseStatus(ctx context.Context, db *sql.DB) string {
	if db == nil {
		return "missing"
	}
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := db.PingContext(checkCtx); err != nil {
		return "error"
	}
	return "connected"
}

func ownerAIProviderStatus() map[string]any {
	return map[string]any{
		"configured": ownerAIProviderConfigured(),
		"provider":   "anthropic",
		"model":      ownerChatModel(),
		"scope":      "owner_panel_only",
	}
}

func ownerTimestamp(ctx context.Context, db *sql.DB, query string) string {
	var value sql.NullTime
	if db == nil {
		return ""
	}
	if err := db.QueryRowContext(ctx, query).Scan(&value); err != nil || !value.Valid {
		return ""
	}
	return value.Time.UTC().Format(time.RFC3339)
}

func buildOwnerChatPrompt(snapshot ownerChatSnapshot, messages []ownerChatMessage, deterministic map[string]any) string {
	snapshotJSON, _ := json.Marshal(snapshot)
	var out strings.Builder
	out.WriteString("CURRENT OPERATIONAL SNAPSHOT:\n")
	out.Write(snapshotJSON)
	out.WriteString("\n\n")
	if deterministic != nil {
		resultJSON, _ := json.Marshal(deterministic)
		out.WriteString("DETERMINISTIC READ-ONLY RESULT FOR THE LATEST QUESTION:\n")
		out.Write(resultJSON)
		out.WriteString("\n\n")
	}
	out.WriteString("CONVERSATION HISTORY:\n")
	for _, message := range messages {
		role := strings.ToUpper(strings.TrimSpace(message.Role))
		if role != "USER" && role != "ASSISTANT" {
			continue
		}
		content := strings.TrimSpace(message.Content)
		if content == "" {
			continue
		}
		out.WriteString(role)
		out.WriteString(": ")
		out.WriteString(content)
		out.WriteString("\n")
	}
	out.WriteString("\nRespond to the latest USER message. Do not repeat the snapshot verbatim.")
	return out.String()
}

func ownerChatTitle(message string) string {
	message = strings.Join(strings.Fields(strings.TrimSpace(message)), " ")
	if message == "" {
		return "Yeni sohbet"
	}
	runes := []rune(message)
	if len(runes) > 54 {
		message = string(runes[:54]) + "…"
	}
	return message
}

func ownerChatIdentity() string {
	owner := normalizeWallet(firstEnv("OWNER_WALLET", "KOSCHEI_OWNER_WALLET"))
	if owner == "" {
		owner = "control-center"
	}
	return "owner:" + owner
}

func ownerChatModel() string {
	return firstNonEmpty(strings.TrimSpace(os.Getenv("ANTHROPIC_OWNER_MODEL")), "claude-sonnet-5")
}

func ownerAIProviderConfigured() bool {
	return strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")) != ""
}

func ownerChatGenerationError(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("Owner AI yanıtı üretilemedi: %s", shortError(err.Error()))
}
