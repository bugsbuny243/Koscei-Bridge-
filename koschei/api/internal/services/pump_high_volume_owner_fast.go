package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

// LatestPumpHighVolumeReportsExact is the owner-panel read path for automatic
// Pump reports. Solana addresses are case-sensitive base58 values, so exact
// equality is required. Completion comes from the canonical investigation job
// ledger; the retired final_verdict_engine table is not a report authority.
func (s *SecurityRadarStore) LatestPumpHighVolumeReportsExact(ctx context.Context, limit int) ([]PumpHighVolumeOwnerItem, error) {
	if s == nil || s.DB == nil {
		return []PumpHighVolumeOwnerItem{}, nil
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.DB.QueryContext(ctx, `
		WITH latest_events AS (
			SELECT DISTINCT ON (e.target) e.id::text, e.target, e.signals, e.created_at
			FROM security_radar_events e
			WHERE e.event_type=$1 AND e.source=$2 AND btrim(e.target)<>''
			ORDER BY e.target, e.created_at DESC, e.id DESC
		)
		SELECT e.id,e.target,e.signals,e.created_at,
		       j.id,j.status,j.completed_at,j.grade,j.verdict,j.ruleset_version,
		       j.signed,j.signature,j.decision_path,j.error_code,j.error_message
		FROM latest_events e
		LEFT JOIN LATERAL (
			SELECT id::text,status,completed_at,
			       COALESCE(result_payload->'final_verdict'->>'grade','') AS grade,
			       COALESCE(result_payload->'final_verdict'->>'verdict','') AS verdict,
			       COALESCE(result_payload->'final_verdict'->>'ruleset_version','') AS ruleset_version,
			       CASE WHEN lower(COALESCE(result_payload->'final_verdict'->>'signed','false'))='true' THEN true ELSE false END AS signed,
			       COALESCE(result_payload->'final_verdict'->>'signature','') AS signature,
			       COALESCE(result_payload->'final_verdict'->'decision_path','[]'::jsonb) AS decision_path,
			       COALESCE(error_code,'') AS error_code,
			       COALESCE(error_message,'') AS error_message
			FROM web3_jobs j
			WHERE j.job_type='canonical_investigation'
			  AND j.network='solana-mainnet'
			  AND j.target=e.target
			  AND COALESCE(j.request_payload->>'source','')=$2
			  AND COALESCE(j.request_payload->>'mode','')=$3
			ORDER BY j.queued_at DESC,j.id DESC
			LIMIT 1
		) j ON true
		ORDER BY COALESCE((e.signals->>'volume_24h_usd')::numeric,0) DESC,e.created_at DESC
		LIMIT $4`, pumpHighVolumeEventType, PumpHighVolumeCanonicalSource, PumpHighVolumeCanonicalMode, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []PumpHighVolumeOwnerItem{}
	for rows.Next() {
		var item PumpHighVolumeOwnerItem
		var signalsRaw, decisionPathRaw []byte
		var jobID, jobStatus, grade, verdict, ruleset, signature, errorCode, errorMessage sql.NullString
		var reportAt sql.NullTime
		var signed bool
		if err := rows.Scan(
			&item.EventID, &item.Target, &signalsRaw, &item.ObservedAt,
			&jobID, &jobStatus, &reportAt, &grade, &verdict, &ruleset,
			&signed, &signature, &decisionPathRaw, &errorCode, &errorMessage,
		); err != nil {
			return nil, err
		}
		item.Signals = map[string]any{}
		_ = json.Unmarshal(signalsRaw, &item.Signals)
		item.Name = pumpSignalString(item.Signals, "token_name", "name")
		item.Symbol = pumpSignalString(item.Signals, "token_symbol", "symbol")
		item.Creator = pumpSignalString(item.Signals, "creator_wallet", "creator")
		item.Volume24hUSD = pumpSignalFloat(item.Signals, "volume_24h_usd")
		item.ThresholdUSD = pumpSignalFloat(item.Signals, "volume_threshold_usd")
		item.PairCount = int(pumpSignalFloat(item.Signals, "volume_pair_count"))
		item.LiquidityUSD = pumpSignalFloat(item.Signals, "liquidity_usd")
		item.MarketCapUSD = pumpSignalFloat(item.Signals, "market_cap_usd")
		item.VolumeProvider = pumpSignalString(item.Signals, "volume_provider")

		item.ReportStatus = "observed"
		if pumpSignalBool(item.Signals, "auto_scan_attempted") {
			item.ReportStatus = "evidence_pending"
		}
		if jobStatus.Valid && strings.TrimSpace(jobStatus.String) != "" {
			item.ReportStatus = strings.TrimSpace(jobStatus.String)
			item.Signals["canonical_job_status"] = item.ReportStatus
			if jobID.Valid {
				item.Signals["canonical_job_id"] = strings.TrimSpace(jobID.String)
			}
			if errorCode.Valid && strings.TrimSpace(errorCode.String) != "" {
				item.Signals["canonical_job_error_code"] = strings.TrimSpace(errorCode.String)
			}
			if errorMessage.Valid && strings.TrimSpace(errorMessage.String) != "" {
				item.Signals["canonical_job_error_message"] = strings.TrimSpace(errorMessage.String)
			}
		}
		if jobStatus.Valid && strings.EqualFold(strings.TrimSpace(jobStatus.String), "completed") {
			item.Verdict = strings.TrimSpace(verdict.String)
			item.Signals["grade"] = strings.TrimSpace(grade.String)
			item.Signals["ruleset_version"] = strings.TrimSpace(ruleset.String)
			item.Signals["signed"] = signed
			if signature.Valid && strings.TrimSpace(signature.String) != "" {
				item.Signals["signature"] = strings.TrimSpace(signature.String)
			}
			decisionPath := []string{}
			if len(decisionPathRaw) > 0 {
				_ = json.Unmarshal(decisionPathRaw, &decisionPath)
			}
			item.Signals["decision_path"] = decisionPath
			if signed {
				item.ReportStatus = "completed"
			} else {
				// A completed worker job is not equivalent to a signed canonical verdict.
				item.ReportStatus = "completed_unsigned"
			}
		}
		if reportAt.Valid {
			value := reportAt.Time.UTC()
			item.ReportAt = &value
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
