package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/web3"
)

const (
	watchlistDefaultThreshold = 50
	watchlistMaxTargets       = 100
	watchlistRefreshBatchMax  = 10
)

var watchlistUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

type watchlistCreateRequest struct {
	Target         string `json:"target"`
	TargetType     string `json:"target_type"`
	Network        string `json:"network"`
	Label          string `json:"label"`
	AlertThreshold int    `json:"alert_threshold"`
}

type watchlistUpdateRequest struct {
	Label          *string `json:"label"`
	Status         *string `json:"status"`
	AlertThreshold *int    `json:"alert_threshold"`
}

type watchlistTarget struct {
	ID             string                  `json:"id"`
	Target         string                  `json:"target"`
	TargetType     string                  `json:"target_type"`
	Network        string                  `json:"network"`
	Label          string                  `json:"label"`
	Status         string                  `json:"status"`
	AlertThreshold int                     `json:"alert_threshold"`
	LastScore      *int                    `json:"last_score"`
	LastRiskLevel  string                  `json:"last_risk_level"`
	LastSnapshot   *watchlistTokenSnapshot `json:"last_snapshot,omitempty"`
	LastCheckedAt  *time.Time              `json:"last_checked_at"`
	NextCheckAt    *time.Time              `json:"next_check_at"`
	UnreadAlerts   int                     `json:"unread_alerts"`
	CreatedAt      time.Time               `json:"created_at"`
	UpdatedAt      time.Time               `json:"updated_at"`
}

type watchlistTokenSnapshot struct {
	Score                int      `json:"score"`
	RiskLevel            string   `json:"risk_level"`
	Supply               string   `json:"supply"`
	Decimals             int      `json:"decimals"`
	MintAuthority        string   `json:"mint_authority"`
	FreezeAuthority      string   `json:"freeze_authority"`
	LargestHolderPercent float64  `json:"largest_holder_percent"`
	TopTenPercent        float64  `json:"top_ten_percent"`
	SourceProvider       string   `json:"source_provider"`
	Findings             []string `json:"findings"`
	CheckedAt            string   `json:"checked_at"`
}

type watchlistAlertCandidate struct {
	EventType     string
	Severity      string
	Title         string
	Message       string
	PreviousValue any
	CurrentValue  any
	Evidence      map[string]any
}

type watchlistAlert struct {
	ID            string         `json:"id"`
	WatchlistID   string         `json:"watchlist_id"`
	Target        string         `json:"target"`
	Label         string         `json:"label"`
	EventType     string         `json:"event_type"`
	Severity      string         `json:"severity"`
	Title         string         `json:"title"`
	Message       string         `json:"message"`
	PreviousValue any            `json:"previous_value"`
	CurrentValue  any            `json:"current_value"`
	Evidence      map[string]any `json:"evidence"`
	Status        string         `json:"status"`
	CreatedAt     time.Time      `json:"created_at"`
	ReadAt        *time.Time     `json:"read_at"`
}

func (h *Handler) WatchlistCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listWatchlistTargets(w, r)
	case http.MethodPost:
		h.createWatchlistTarget(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) WatchlistItem(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/watchlist/"), "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || !watchlistUUIDPattern.MatchString(parts[0]) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_watchlist_id"})
		return
	}
	id := parts[0]
	if len(parts) == 2 && parts[1] == "refresh" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h.refreshWatchlistTargetHTTP(w, r, id)
		return
	}
	if len(parts) != 1 {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPatch:
		h.updateWatchlistTarget(w, r, id)
	case http.MethodDelete:
		h.deleteWatchlistTarget(w, r, id)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) WatchlistRefresh(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	limit := 5
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > watchlistRefreshBatchMax {
		limit = watchlistRefreshBatchMax
	}

	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT id::text
		FROM watchlist_targets
		WHERE auth_subject=$1 AND status='active'
		ORDER BY COALESCE(last_checked_at, to_timestamp(0)) ASC
		LIMIT $2`, claims.Sub, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()

	type refreshResult struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		AlertCount int    `json:"alert_count"`
		Error      string `json:"error,omitempty"`
	}
	results := make([]refreshResult, 0, len(ids))
	for _, id := range ids {
		target, alerts, refreshErr := h.refreshWatchlistTarget(r.Context(), claims.Sub, id)
		item := refreshResult{ID: id, Status: "completed", AlertCount: alerts}
		if refreshErr != nil {
			item.Status = "failed"
			item.Error = publicWatchlistError(refreshErr)
		} else {
			item.ID = target.ID
		}
		results = append(results, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "refreshed": len(results), "results": results})
}

func (h *Handler) WatchlistAlerts(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.Method == http.MethodPost {
		res, err := h.DB.ExecContext(r.Context(), `UPDATE watchlist_alerts SET status='read', read_at=COALESCE(read_at,now()) WHERE auth_subject=$1 AND status='new'`, claims.Sub)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
			return
		}
		count, _ := res.RowsAffected()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "marked_read": count})
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	limit := 100
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT a.id::text,a.watchlist_id::text,t.target,t.label,a.event_type,a.severity,a.title,a.message,
		       a.previous_value,a.current_value,a.evidence,a.status,a.created_at,a.read_at
		FROM watchlist_alerts a
		JOIN watchlist_targets t ON t.id=a.watchlist_id
		WHERE a.auth_subject=$1
		ORDER BY a.created_at DESC
		LIMIT $2`, claims.Sub, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	defer rows.Close()
	alerts := []watchlistAlert{}
	for rows.Next() {
		var item watchlistAlert
		var previousRaw, currentRaw, evidenceRaw []byte
		var readAt sql.NullTime
		if err := rows.Scan(&item.ID, &item.WatchlistID, &item.Target, &item.Label, &item.EventType, &item.Severity, &item.Title, &item.Message, &previousRaw, &currentRaw, &evidenceRaw, &item.Status, &item.CreatedAt, &readAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
			return
		}
		item.PreviousValue = decodeJSONValue(previousRaw)
		item.CurrentValue = decodeJSONValue(currentRaw)
		item.Evidence = decodeJSONMap(evidenceRaw)
		if readAt.Valid {
			value := readAt.Time
			item.ReadAt = &value
		}
		alerts = append(alerts, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "alerts": alerts})
}

func (h *Handler) createWatchlistTarget(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req watchlistCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	req.TargetType = strings.ToLower(strings.TrimSpace(req.TargetType))
	req.Network = strings.ToLower(strings.TrimSpace(req.Network))
	req.Label = strings.TrimSpace(req.Label)
	if req.Target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_required"})
		return
	}
	if len(req.Target) > 128 || len(req.Label) > 80 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "field_too_long"})
		return
	}
	if req.TargetType == "" {
		req.TargetType = "token"
	}
	if req.TargetType != "token" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "only_token_watchlists_are_enabled"})
		return
	}
	if req.Network == "" {
		req.Network = "solana-mainnet"
	}
	if req.Network != "solana-mainnet" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_network"})
		return
	}
	if req.AlertThreshold == 0 {
		req.AlertThreshold = watchlistDefaultThreshold
	}
	if req.AlertThreshold < 0 || req.AlertThreshold > 100 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_alert_threshold"})
		return
	}
	var count int
	if err := h.DB.QueryRowContext(r.Context(), `SELECT count(*) FROM watchlist_targets WHERE auth_subject=$1`, claims.Sub).Scan(&count); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	if count >= watchlistMaxTargets {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "watchlist_limit_reached", "max_targets": watchlistMaxTargets})
		return
	}

	var id string
	err := h.DB.QueryRowContext(r.Context(), `
		INSERT INTO watchlist_targets (auth_subject,email,target,target_type,network,label,alert_threshold,next_check_at)
		VALUES ($1,lower($2),$3,$4,$5,$6,$7,now())
		ON CONFLICT (auth_subject,network,target) DO UPDATE SET
			label=EXCLUDED.label, alert_threshold=EXCLUDED.alert_threshold, status='active', updated_at=now()
		RETURNING id::text`, claims.Sub, normalizedClaimEmail(claims), req.Target, req.TargetType, req.Network, req.Label, req.AlertThreshold).Scan(&id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	target, alertCount, refreshErr := h.refreshWatchlistTarget(r.Context(), claims.Sub, id)
	response := map[string]any{"ok": true, "created": true, "target": target, "alert_count": alertCount}
	if refreshErr != nil {
		response["refresh_error"] = publicWatchlistError(refreshErr)
	}
	writeJSON(w, http.StatusCreated, response)
}

func (h *Handler) listWatchlistTargets(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT t.id::text,t.target,t.target_type,t.network,t.label,t.status,t.alert_threshold,t.last_score,
		       t.last_risk_level,t.last_snapshot,t.last_checked_at,t.next_check_at,t.created_at,t.updated_at,
		       (SELECT count(*) FROM watchlist_alerts a WHERE a.watchlist_id=t.id AND a.status='new')
		FROM watchlist_targets t
		WHERE t.auth_subject=$1
		ORDER BY t.updated_at DESC`, claims.Sub)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	defer rows.Close()
	targets := []watchlistTarget{}
	for rows.Next() {
		item, scanErr := scanWatchlistTarget(rows)
		if scanErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
			return
		}
		targets = append(targets, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "targets": targets, "max_targets": watchlistMaxTargets})
}

func (h *Handler) updateWatchlistTarget(w http.ResponseWriter, r *http.Request, id string) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req watchlistUpdateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	if req.Label != nil && len(strings.TrimSpace(*req.Label)) > 80 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "label_too_long"})
		return
	}
	if req.Status != nil {
		status := strings.ToLower(strings.TrimSpace(*req.Status))
		if status != "active" && status != "paused" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_status"})
			return
		}
		*req.Status = status
	}
	if req.AlertThreshold != nil && (*req.AlertThreshold < 0 || *req.AlertThreshold > 100) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_alert_threshold"})
		return
	}
	res, err := h.DB.ExecContext(r.Context(), `
		UPDATE watchlist_targets SET
			label=COALESCE($1,label), status=COALESCE($2,status), alert_threshold=COALESCE($3,alert_threshold),
			next_check_at=CASE WHEN COALESCE($2,status)='active' THEN COALESCE(next_check_at,now()) ELSE next_check_at END,
			updated_at=now()
		WHERE id=$4 AND auth_subject=$5`, nullableTrimmedString(req.Label), req.Status, req.AlertThreshold, id, claims.Sub)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	count, _ := res.RowsAffected()
	if count == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "watchlist_not_found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) deleteWatchlistTarget(w http.ResponseWriter, r *http.Request, id string) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM watchlist_targets WHERE id=$1 AND auth_subject=$2`, id, claims.Sub)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	count, _ := res.RowsAffected()
	if count == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "watchlist_not_found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": id})
}

func (h *Handler) refreshWatchlistTargetHTTP(w http.ResponseWriter, r *http.Request, id string) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	target, alerts, err := h.refreshWatchlistTarget(r.Context(), claims.Sub, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "watchlist_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": publicWatchlistError(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "target": target, "alert_count": alerts})
}

func (h *Handler) refreshWatchlistTarget(ctx context.Context, authSubject, id string) (watchlistTarget, int, error) {
	var target watchlistTarget
	var oldScore sql.NullInt64
	var oldSnapshotRaw []byte
	err := h.DB.QueryRowContext(ctx, `
		SELECT id::text,target,target_type,network,label,status,alert_threshold,last_score,last_risk_level,last_snapshot,
		       last_checked_at,next_check_at,created_at,updated_at
		FROM watchlist_targets
		WHERE id=$1 AND auth_subject=$2`, id, authSubject).
		Scan(&target.ID, &target.Target, &target.TargetType, &target.Network, &target.Label, &target.Status, &target.AlertThreshold,
			&oldScore, &target.LastRiskLevel, &oldSnapshotRaw, nullableTimeDestination(&target.LastCheckedAt), nullableTimeDestination(&target.NextCheckAt), &target.CreatedAt, &target.UpdatedAt)
	if err != nil {
		return target, 0, err
	}
	if target.TargetType != "token" {
		return target, 0, fmt.Errorf("unsupported watchlist target type")
	}

	scanCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	result, err := h.tokenService().ScanToken(scanCtx, target.Network, target.Target)
	if err != nil {
		_, _ = h.DB.ExecContext(ctx, `UPDATE watchlist_targets SET last_checked_at=now(),next_check_at=now()+interval '1 hour',updated_at=now() WHERE id=$1 AND auth_subject=$2`, id, authSubject)
		return target, 0, err
	}
	current := snapshotFromTokenRisk(result)
	var previous *watchlistTokenSnapshot
	if len(oldSnapshotRaw) > 0 && string(oldSnapshotRaw) != "{}" {
		var decoded watchlistTokenSnapshot
		if json.Unmarshal(oldSnapshotRaw, &decoded) == nil {
			previous = &decoded
		}
	}
	alerts := compareWatchlistSnapshots(previous, current, target.AlertThreshold)
	currentRaw, _ := json.Marshal(current)

	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		return target, 0, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
		UPDATE watchlist_targets SET last_score=$1,last_risk_level=$2,last_snapshot=$3::jsonb,last_checked_at=now(),
		       next_check_at=now()+interval '1 hour',updated_at=now()
		WHERE id=$4 AND auth_subject=$5`, current.Score, current.RiskLevel, string(currentRaw), id, authSubject)
	if err != nil {
		return target, 0, err
	}
	for _, alert := range alerts {
		previousRaw, _ := json.Marshal(alert.PreviousValue)
		currentValueRaw, _ := json.Marshal(alert.CurrentValue)
		evidenceRaw, _ := json.Marshal(alert.Evidence)
		_, err = tx.ExecContext(ctx, `
			INSERT INTO watchlist_alerts (watchlist_id,auth_subject,event_type,severity,title,message,previous_value,current_value,evidence)
			VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb)`, id, authSubject, alert.EventType, alert.Severity, alert.Title, alert.Message, string(previousRaw), string(currentValueRaw), string(evidenceRaw))
		if err != nil {
			return target, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return target, 0, err
	}

	now := time.Now().UTC()
	next := now.Add(time.Hour)
	target.LastScore = &current.Score
	target.LastRiskLevel = current.RiskLevel
	target.LastSnapshot = &current
	target.LastCheckedAt = &now
	target.NextCheckAt = &next
	target.UpdatedAt = now
	return target, len(alerts), nil
}

func snapshotFromTokenRisk(result web3.TokenRiskResult) watchlistTokenSnapshot {
	return watchlistTokenSnapshot{
		Score:                result.Score,
		RiskLevel:            result.RiskLevel,
		Supply:               result.Token.SupplyRaw,
		Decimals:             result.Token.Decimals,
		MintAuthority:        pointerString(result.Token.MintAuthority),
		FreezeAuthority:      pointerString(result.Token.FreezeAuthority),
		LargestHolderPercent: roundPercent(result.Token.LargestHolderPercent),
		TopTenPercent:        roundPercent(result.Token.TopTenPercent),
		SourceProvider:       result.Token.SourceProvider,
		Findings:             append([]string(nil), result.Findings...),
		CheckedAt:            time.Now().UTC().Format(time.RFC3339),
	}
}

func compareWatchlistSnapshots(previous *watchlistTokenSnapshot, current watchlistTokenSnapshot, threshold int) []watchlistAlertCandidate {
	if previous == nil {
		return []watchlistAlertCandidate{}
	}
	alerts := []watchlistAlertCandidate{}
	delta := current.Score - previous.Score
	if delta <= -15 {
		severity := watchlistSeverity(current.Score)
		alerts = append(alerts, watchlistAlertCandidate{
			EventType: "risk_increased", Severity: severity, Title: "Risk seviyesi yükseldi",
			Message:       fmt.Sprintf("Güvenlik skoru %d puan düşerek %d oldu.", -delta, current.Score),
			PreviousValue: previous.Score, CurrentValue: current.Score,
			Evidence: map[string]any{"risk_level": current.RiskLevel, "findings": current.Findings},
		})
	}
	if previous.Score >= threshold && current.Score < threshold {
		alerts = append(alerts, watchlistAlertCandidate{
			EventType: "threshold_crossed", Severity: watchlistSeverity(current.Score), Title: "Güvenlik tabanı aşıldı",
			Message:       fmt.Sprintf("Skor %d güvenlik tabanının altına düştü.", threshold),
			PreviousValue: previous.Score, CurrentValue: current.Score,
			Evidence: map[string]any{"threshold": threshold, "risk_level": current.RiskLevel},
		})
	}
	if previous.MintAuthority != current.MintAuthority {
		alerts = append(alerts, authorityWatchlistAlert("mint_authority_changed", "Mint authority değişti", previous.MintAuthority, current.MintAuthority))
	}
	if previous.FreezeAuthority != current.FreezeAuthority {
		alerts = append(alerts, authorityWatchlistAlert("freeze_authority_changed", "Freeze authority değişti", previous.FreezeAuthority, current.FreezeAuthority))
	}
	if current.LargestHolderPercent-previous.LargestHolderPercent >= 10 {
		alerts = append(alerts, watchlistAlertCandidate{
			EventType: "holder_concentration_increased", Severity: "high", Title: "Holder yoğunluğu yükseldi",
			Message:       "En büyük token hesabının arz payı en az 10 puan arttı.",
			PreviousValue: previous.LargestHolderPercent, CurrentValue: current.LargestHolderPercent,
			Evidence: map[string]any{"top_ten_percent": current.TopTenPercent},
		})
	}
	if previous.Supply != "" && current.Supply != "" && previous.Supply != current.Supply {
		alerts = append(alerts, watchlistAlertCandidate{
			EventType: "supply_changed", Severity: "high", Title: "Token arzı değişti",
			Message:       "Gözlenen ham token arzı önceki kontrolden farklı.",
			PreviousValue: previous.Supply, CurrentValue: current.Supply,
			Evidence: map[string]any{"mint_authority": current.MintAuthority},
		})
	}
	return deduplicateWatchlistAlerts(alerts)
}

func authorityWatchlistAlert(eventType, title, previous, current string) watchlistAlertCandidate {
	severity := "high"
	message := "Yetki adresi değişti."
	if previous == "" && current != "" {
		severity = "critical"
		message = "Daha önce kapalı olan yetki yeniden aktif görünüyor."
	} else if previous != "" && current == "" {
		severity = "info"
		message = "Yetki kapatıldı."
	}
	return watchlistAlertCandidate{EventType: eventType, Severity: severity, Title: title, Message: message, PreviousValue: previous, CurrentValue: current, Evidence: map[string]any{"previous": previous, "current": current}}
}

func deduplicateWatchlistAlerts(input []watchlistAlertCandidate) []watchlistAlertCandidate {
	seen := map[string]struct{}{}
	out := make([]watchlistAlertCandidate, 0, len(input))
	for _, item := range input {
		key := item.EventType + "|" + fmt.Sprint(item.CurrentValue)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return watchlistSeverityRank(out[i].Severity) > watchlistSeverityRank(out[j].Severity)
	})
	return out
}

func watchlistSeverity(score int) string {
	switch {
	case score < 25:
		return "critical"
	case score < 40:
		return "high"
	case score < 70:
		return "medium"
	default:
		return "low"
	}
}

func watchlistSeverityRank(value string) int {
	switch value {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func scanWatchlistTarget(rows *sql.Rows) (watchlistTarget, error) {
	var item watchlistTarget
	var score sql.NullInt64
	var snapshotRaw []byte
	var checkedAt, nextAt sql.NullTime
	err := rows.Scan(&item.ID, &item.Target, &item.TargetType, &item.Network, &item.Label, &item.Status, &item.AlertThreshold,
		&score, &item.LastRiskLevel, &snapshotRaw, &checkedAt, &nextAt, &item.CreatedAt, &item.UpdatedAt, &item.UnreadAlerts)
	if err != nil {
		return item, err
	}
	if score.Valid {
		value := int(score.Int64)
		item.LastScore = &value
	}
	if len(snapshotRaw) > 0 && string(snapshotRaw) != "{}" {
		var snapshot watchlistTokenSnapshot
		if json.Unmarshal(snapshotRaw, &snapshot) == nil {
			item.LastSnapshot = &snapshot
		}
	}
	if checkedAt.Valid {
		value := checkedAt.Time
		item.LastCheckedAt = &value
	}
	if nextAt.Valid {
		value := nextAt.Time
		item.NextCheckAt = &value
	}
	return item, nil
}

func decodeJSONValue(raw []byte) any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return map[string]any{}
	}
	return value
}

func decodeJSONMap(raw []byte) map[string]any {
	value := map[string]any{}
	_ = json.Unmarshal(raw, &value)
	return value
}

func pointerString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func nullableTrimmedString(value *string) any {
	if value == nil {
		return nil
	}
	return strings.TrimSpace(*value)
}

func nullableTimeDestination(target **time.Time) any {
	return &nullableTimeScanner{target: target}
}

type nullableTimeScanner struct{ target **time.Time }

func (s *nullableTimeScanner) Scan(src any) error {
	if src == nil {
		*s.target = nil
		return nil
	}
	value, ok := src.(time.Time)
	if !ok {
		return fmt.Errorf("unsupported time value")
	}
	*s.target = &value
	return nil
}

func publicWatchlistError(err error) string {
	if err == nil {
		return ""
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "429"), strings.Contains(lower, "rate limit"):
		return "rpc_capacity_exhausted"
	case strings.Contains(lower, "timeout"), strings.Contains(lower, "deadline"):
		return "watchlist_refresh_timeout"
	default:
		return "watchlist_refresh_failed"
	}
}
