package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/router"
)

type ownerChatInput struct {
	ThreadID string `json:"thread_id"`
	Message  string `json:"message"`
}

type ownerChatThread struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ownerChatMessage struct {
	ID        string    `json:"id"`
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

func (h *Handler) OwnerChat(w http.ResponseWriter, r *http.Request) {
	if !h.ownerAuth(w, r) {
		return
	}
	if h.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database_unavailable"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.ownerChatHistory(w, r)
	case http.MethodPost:
		h.ownerChatSend(w, r)
	case http.MethodDelete:
		h.ownerChatDelete(w, r)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
	}
}

func (h *Handler) ownerChatHistory(w http.ResponseWriter, r *http.Request) {
	ownerID := ownerChatIdentity()
	threads, err := loadOwnerChatThreads(r.Context(), h.DB, ownerID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "owner_chat_history_unavailable"})
		return
	}
	threadID := strings.TrimSpace(r.URL.Query().Get("thread_id"))
	if threadID == "" && len(threads) > 0 {
		threadID = threads[0].ID
	}
	messages := []ownerChatMessage{}
	if threadID != "" {
		if !ownerChatThreadBelongsTo(r.Context(), h.DB, threadID, ownerID) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "owner_chat_thread_not_found"})
			return
		}
		messages, err = loadOwnerChatMessages(r.Context(), h.DB, threadID, 100)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "owner_chat_messages_unavailable"})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"ai_ready":  ownerAIProviderConfigured(),
		"provider":  "together",
		"model":     ownerChatModel(),
		"thread_id": threadID,
		"threads":   threads,
		"messages":  messages,
	})
}

func (h *Handler) ownerChatSend(w http.ResponseWriter, r *http.Request) {
	var input ownerChatInput
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	message := normalizeOwnerChatText(input.Message, 4000)
	if message == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message_required"})
		return
	}
	if !ownerAIProviderConfigured() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ai_provider_not_configured"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
	defer cancel()
	ownerID := ownerChatIdentity()
	threadID := strings.TrimSpace(input.ThreadID)
	createdThread := false
	if threadID == "" {
		threadID = generateID()
		if _, err := h.DB.ExecContext(ctx, `
			INSERT INTO owner_chat_threads (id,owner_id,title,created_at,updated_at)
			VALUES ($1,$2,$3,now(),now())`, threadID, ownerID, ownerChatTitle(message)); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "owner_chat_thread_create_failed"})
			return
		}
		createdThread = true
	} else if !ownerChatThreadBelongsTo(ctx, h.DB, threadID, ownerID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "owner_chat_thread_not_found"})
		return
	}

	userMessage := ownerChatMessage{ID: generateID(), Role: "user", Content: message, CreatedAt: time.Now().UTC()}
	if _, err := h.DB.ExecContext(ctx, `
		INSERT INTO owner_chat_messages (id,thread_id,role,content,context_snapshot,created_at)
		VALUES ($1,$2,'user',$3,'{}'::jsonb,now())`, userMessage.ID, threadID, userMessage.Content); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "owner_chat_message_save_failed"})
		return
	}
	_, _ = h.DB.ExecContext(ctx, `UPDATE owner_chat_threads SET updated_at=now() WHERE id=$1 AND owner_id=$2`, threadID, ownerID)

	history, err := loadOwnerChatMessages(ctx, h.DB, threadID, 18)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "owner_chat_history_unavailable"})
		return
	}
	history = ownerChatWindow(history, 22000)
	snapshot := h.buildOwnerChatSnapshot(ctx)

	var deterministic map[string]any
	if intent, result, humanMessage, ok := h.routeOwnerBrainCommand(ctx, message); ok {
		deterministic = map[string]any{"intent": intent, "message": humanMessage, "result": result}
	}
	prompt := buildOwnerChatPrompt(snapshot, history, deterministic)
	aiReply, err := router.Chat(ctx, router.ChatRequest{System: ownerChatSystemPrompt, Prompt: prompt, Model: ownerChatModel(), Timeout: 65 * time.Second, MaxTokens: 1600, Temperature: 0.2})
	reply := aiReply.Content
	if err != nil {
		_, _ = h.DB.ExecContext(ctx, `INSERT INTO ai_command_logs (command,output,status,created_at) VALUES ($1,$2,'error',now())`, message, ownerChatGenerationError(err))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "owner_chat_generation_failed", "detail": shortError(err.Error())})
		return
	}
	reply = normalizeOwnerChatText(reply, 12000)
	if reply == "" {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "owner_chat_empty_response"})
		return
	}

	snapshotJSON, _ := json.Marshal(snapshot)
	assistantMessage := ownerChatMessage{ID: generateID(), Role: "assistant", Content: reply, CreatedAt: time.Now().UTC()}
	if _, err := h.DB.ExecContext(ctx, `
		INSERT INTO owner_chat_messages (id,thread_id,role,content,context_snapshot,created_at)
		VALUES ($1,$2,'assistant',$3,$4::jsonb,now())`, assistantMessage.ID, threadID, assistantMessage.Content, string(snapshotJSON)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "owner_chat_response_save_failed"})
		return
	}
	_, _ = h.DB.ExecContext(ctx, `UPDATE owner_chat_threads SET updated_at=now() WHERE id=$1 AND owner_id=$2`, threadID, ownerID)
	_, _ = h.DB.ExecContext(ctx, `INSERT INTO ai_command_logs (command,output,status,created_at) VALUES ($1,$2,'completed',now())`, message, reply)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"thread_id":         threadID,
		"created_thread":    createdThread,
		"provider":          aiReply.Provider,
		"model":             aiReply.Model,
		"user_message":      userMessage,
		"assistant_message": assistantMessage,
	})
}

func (h *Handler) ownerChatDelete(w http.ResponseWriter, r *http.Request) {
	threadID := strings.TrimSpace(r.URL.Query().Get("thread_id"))
	if threadID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "thread_id_required"})
		return
	}
	result, err := h.DB.ExecContext(r.Context(), `DELETE FROM owner_chat_threads WHERE id=$1 AND owner_id=$2`, threadID, ownerChatIdentity())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "owner_chat_delete_failed"})
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "owner_chat_thread_not_found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": threadID})
}

func loadOwnerChatThreads(ctx context.Context, db *sql.DB, ownerID string) ([]ownerChatThread, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id,title,created_at,updated_at
		FROM owner_chat_threads
		WHERE owner_id=$1
		ORDER BY updated_at DESC
		LIMIT 30`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	threads := []ownerChatThread{}
	for rows.Next() {
		var thread ownerChatThread
		if err := rows.Scan(&thread.ID, &thread.Title, &thread.CreatedAt, &thread.UpdatedAt); err != nil {
			return nil, err
		}
		threads = append(threads, thread)
	}
	return threads, rows.Err()
}

func loadOwnerChatMessages(ctx context.Context, db *sql.DB, threadID string, limit int) ([]ownerChatMessage, error) {
	if limit <= 0 || limit > 100 {
		limit = 18
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id,role,content,created_at
		FROM (
			SELECT id,role,content,created_at
			FROM owner_chat_messages
			WHERE thread_id=$1
			ORDER BY created_at DESC
			LIMIT $2
		) recent
		ORDER BY created_at ASC`, threadID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	messages := []ownerChatMessage{}
	for rows.Next() {
		var message ownerChatMessage
		if err := rows.Scan(&message.ID, &message.Role, &message.Content, &message.CreatedAt); err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	return messages, rows.Err()
}

func ownerChatThreadBelongsTo(ctx context.Context, db *sql.DB, threadID, ownerID string) bool {
	var exists bool
	if db == nil || threadID == "" || ownerID == "" {
		return false
	}
	_ = db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM owner_chat_threads WHERE id=$1 AND owner_id=$2)`, threadID, ownerID).Scan(&exists)
	return exists
}

func normalizeOwnerChatText(value string, maxRunes int) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\x00", ""))
	if maxRunes <= 0 {
		return value
	}
	runes := []rune(value)
	if len(runes) > maxRunes {
		value = string(runes[:maxRunes])
	}
	return strings.TrimSpace(value)
}

func ownerChatWindow(messages []ownerChatMessage, maxChars int) []ownerChatMessage {
	if maxChars <= 0 || len(messages) == 0 {
		return messages
	}
	total := 0
	start := len(messages)
	for i := len(messages) - 1; i >= 0; i-- {
		length := len([]rune(messages[i].Content))
		if total+length > maxChars && start < len(messages) {
			break
		}
		total += length
		start = i
	}
	return messages[start:]
}
