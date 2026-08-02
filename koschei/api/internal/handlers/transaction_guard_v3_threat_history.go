package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	guardV3ThreatSubjectLimit = 48
	guardV3ThreatRowLimit     = 240
)

type transactionGuardThreatCandidate struct {
	Address string
	Roles   []string
}

type transactionGuardThreatMatch struct {
	ModuleID       string   `json:"module_id"`
	TargetType     string   `json:"target_type,omitempty"`
	RiskLevel      string   `json:"risk_level"`
	RiskIndex      int      `json:"risk_index"`
	Grade          string   `json:"grade,omitempty"`
	Verdict        string   `json:"verdict,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	Source         string   `json:"source,omitempty"`
	ObservedAt     string   `json:"observed_at"`
	Evidence       []string `json:"evidence"`
}

type transactionGuardThreatSubject struct {
	Address            string                        `json:"address"`
	Roles              []string                      `json:"roles"`
	Matched            bool                          `json:"matched"`
	SignedVerdictCount int                           `json:"signed_verdict_count"`
	HighestRiskLevel   string                        `json:"highest_risk_level,omitempty"`
	HighestRiskIndex   int                           `json:"highest_risk_index"`
	LatestObservedAt   string                        `json:"latest_observed_at,omitempty"`
	Modules            []string                      `json:"modules"`
	Matches            []transactionGuardThreatMatch `json:"matches"`
}

type transactionGuardThreatHistoryAnalysis struct {
	Requested        bool                            `json:"requested"`
	Required         bool                            `json:"required"`
	Available        bool                            `json:"available"`
	Complete         bool                            `json:"complete"`
	Status           string                          `json:"status"`
	SubjectsChecked  int                             `json:"subjects_checked"`
	SubjectsMatched  int                             `json:"subjects_matched"`
	HighestRiskLevel string                          `json:"highest_risk_level,omitempty"`
	HighestRiskIndex int                             `json:"highest_risk_index"`
	Subjects         []transactionGuardThreatSubject `json:"subjects"`
	Limitations      []string                        `json:"limitations"`
}

type transactionGuardThreatRow struct {
	Target         string
	TargetType     string
	ModuleID       string
	RiskIndex      int
	RiskLevel      string
	Grade          string
	Verdict        string
	Recommendation string
	Evidence       []string
	Source         string
	ObservedAt     time.Time
}

func transactionGuardV3ThreatCandidates(decoded transactionGuardDecodedTransaction, wallet string) []transactionGuardThreatCandidate {
	ignored := stringSet(guardBuiltinPrograms())
	wallet = strings.TrimSpace(wallet)
	if wallet != "" {
		ignored[wallet] = true
	}

	rolesByAddress := map[string]map[string]bool{}
	canonical := map[string]string{}
	add := func(address, role string) {
		address = strings.TrimSpace(address)
		role = strings.TrimSpace(role)
		if !looksLikeGuardPubkey(address) || role == "" || ignored[address] {
			return
		}
		key := strings.ToLower(address)
		if _, ok := rolesByAddress[key]; !ok {
			rolesByAddress[key] = map[string]bool{}
			canonical[key] = address
		}
		rolesByAddress[key][role] = true
	}

	for _, program := range decoded.ProgramIDs {
		add(program, "invoked_program")
	}
	for _, transfer := range decoded.SOLTransfers {
		add(transfer.Recipient, "sol_recipient")
		if transfer.Owner != "" {
			add(transfer.Owner, "created_account_owner_program")
		}
	}
	for _, operation := range decoded.TokenOperations {
		switch operation.Kind {
		case "transfer", "transfer_checked":
			add(operation.Destination, "token_destination_account")
		case "approve", "approve_checked":
			add(operation.Delegate, "token_delegate")
		case "set_authority":
			if operation.NewAuthority != "revoked" {
				add(operation.NewAuthority, "new_token_authority")
			}
		case "close_account":
			add(operation.Destination, "rent_recipient")
		case "freeze_account", "thaw_account":
			add(operation.Authority, "freeze_authority")
		}
	}

	keys := make([]string, 0, len(rolesByAddress))
	for key := range rolesByAddress {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > guardV3ThreatSubjectLimit {
		keys = keys[:guardV3ThreatSubjectLimit]
	}
	out := make([]transactionGuardThreatCandidate, 0, len(keys))
	for _, key := range keys {
		roles := make([]string, 0, len(rolesByAddress[key]))
		for role := range rolesByAddress[key] {
			roles = append(roles, role)
		}
		sort.Strings(roles)
		out = append(out, transactionGuardThreatCandidate{Address: canonical[key], Roles: roles})
	}
	return out
}

func (h *Handler) collectTransactionGuardV3ThreatHistory(ctx context.Context, network string, decoded transactionGuardDecodedTransaction, wallet string) (transactionGuardThreatHistoryAnalysis, []transactionFirewallFinding) {
	required := envBool("TRANSACTION_GUARD_REQUIRE_THREAT_HISTORY", false)
	candidates := transactionGuardV3ThreatCandidates(decoded, wallet)
	analysis := transactionGuardThreatHistoryAnalysis{
		Requested: len(candidates) > 0, Required: required, Status: "no_subjects",
		Complete: len(candidates) == 0, SubjectsChecked: len(candidates),
		Subjects: []transactionGuardThreatSubject{}, Limitations: []string{},
	}
	if len(candidates) == 0 {
		return analysis, nil
	}

	db := (*sql.DB)(nil)
	if h != nil {
		db = h.DBRead
		if db == nil {
			db = h.DB
		}
	}
	if db == nil {
		analysis.Status = "source_unavailable"
		analysis.Limitations = append(analysis.Limitations, "Koschei threat-history storage is unavailable; no historical safety claim was made.")
		return analysis, transactionGuardThreatUnavailableFindings(required, "database handle is unavailable")
	}

	queryCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	if !ownerTableExists(queryCtx, db, "security_radar_verdicts") {
		analysis.Status = "source_unavailable"
		analysis.Limitations = append(analysis.Limitations, "The signed Security Radar verdict table is unavailable; no historical safety claim was made.")
		return analysis, transactionGuardThreatUnavailableFindings(required, "signed verdict table is unavailable")
	}

	rows, err := queryTransactionGuardThreatRows(queryCtx, db, network, candidates)
	if err != nil {
		analysis.Status = "source_unavailable"
		analysis.Limitations = append(analysis.Limitations, "Signed historical verdicts could not be read within the Guard evidence budget.")
		return analysis, transactionGuardThreatUnavailableFindings(required, compactGuardV3Evidence(err.Error()))
	}
	analysis, findings := aggregateTransactionGuardThreatRows(candidates, rows, required)
	analysis.Available = true
	analysis.Complete = true
	analysis.Requested = true
	analysis.Required = required
	analysis.Status = "complete_no_matches"
	if analysis.SubjectsMatched > 0 {
		analysis.Status = "matches_observed"
	}
	analysis.Limitations = append(analysis.Limitations,
		"Threat history uses Koschei-signed Security Radar verdicts for exact on-chain address matches.",
		"An address match is historical risk evidence, not proof of real-world identity or intent.",
	)
	return analysis, findings
}

func queryTransactionGuardThreatRows(ctx context.Context, db *sql.DB, network string, candidates []transactionGuardThreatCandidate) ([]transactionGuardThreatRow, error) {
	if db == nil || len(candidates) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(candidates)+1)
	args = append(args, strings.TrimSpace(network))
	placeholders := make([]string, 0, len(candidates))
	for index, candidate := range candidates {
		args = append(args, strings.ToLower(strings.TrimSpace(candidate.Address)))
		placeholders = append(placeholders, fmt.Sprintf("$%d", index+2))
	}
	query := `
		SELECT target, target_type, module_id, risk_index, risk_level, grade,
		       verdict, recommendation, evidence, source, created_at
		FROM security_radar_verdicts
		WHERE network=$1 AND signed=true
		  AND lower(target) IN (` + strings.Join(placeholders, ",") + `)
		ORDER BY created_at DESC
		LIMIT ` + fmt.Sprintf("%d", guardV3ThreatRowLimit)

	result, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer result.Close()

	rows := []transactionGuardThreatRow{}
	for result.Next() {
		var target, targetType, moduleID, riskLevel, grade, verdict, recommendation, source sql.NullString
		var riskIndex sql.NullInt64
		var evidenceRaw []byte
		var observedAt time.Time
		if err := result.Scan(&target, &targetType, &moduleID, &riskIndex, &riskLevel, &grade, &verdict, &recommendation, &evidenceRaw, &source, &observedAt); err != nil {
			return nil, err
		}
		rows = append(rows, transactionGuardThreatRow{
			Target: target.String, TargetType: targetType.String, ModuleID: moduleID.String,
			RiskIndex: int(riskIndex.Int64), RiskLevel: strings.ToLower(strings.TrimSpace(riskLevel.String)),
			Grade: grade.String, Verdict: verdict.String, Recommendation: recommendation.String,
			Evidence: transactionGuardThreatEvidenceStrings(evidenceRaw), Source: source.String, ObservedAt: observedAt.UTC(),
		})
	}
	return rows, result.Err()
}

func aggregateTransactionGuardThreatRows(candidates []transactionGuardThreatCandidate, rows []transactionGuardThreatRow, required bool) (transactionGuardThreatHistoryAnalysis, []transactionFirewallFinding) {
	analysis := transactionGuardThreatHistoryAnalysis{
		Requested: len(candidates) > 0, Required: required, Complete: true, Available: true,
		Status: "complete_no_matches", SubjectsChecked: len(candidates), Subjects: []transactionGuardThreatSubject{}, Limitations: []string{},
	}
	candidateIndex := map[string]transactionGuardThreatCandidate{}
	for _, candidate := range candidates {
		candidateIndex[strings.ToLower(candidate.Address)] = candidate
	}
	subjects := map[string]*transactionGuardThreatSubject{}
	for _, row := range rows {
		key := strings.ToLower(strings.TrimSpace(row.Target))
		candidate, ok := candidateIndex[key]
		if !ok {
			continue
		}
		subject := subjects[key]
		if subject == nil {
			subject = &transactionGuardThreatSubject{
				Address: candidate.Address, Roles: append([]string{}, candidate.Roles...), Matched: true,
				Modules: []string{}, Matches: []transactionGuardThreatMatch{}, HighestRiskLevel: "low",
			}
			subjects[key] = subject
		}
		subject.SignedVerdictCount++
		if riskRank(row.RiskLevel, row.RiskIndex) > riskRank(subject.HighestRiskLevel, subject.HighestRiskIndex) {
			subject.HighestRiskLevel = normalizedThreatRiskLevel(row.RiskLevel, row.RiskIndex)
			subject.HighestRiskIndex = row.RiskIndex
		}
		if subject.LatestObservedAt == "" || row.ObservedAt.Format(time.RFC3339) > subject.LatestObservedAt {
			subject.LatestObservedAt = row.ObservedAt.Format(time.RFC3339)
		}
		if row.ModuleID != "" && !containsGuardString(subject.Modules, row.ModuleID) {
			subject.Modules = append(subject.Modules, row.ModuleID)
		}
		if len(subject.Matches) < 5 {
			subject.Matches = append(subject.Matches, transactionGuardThreatMatch{
				ModuleID: row.ModuleID, TargetType: row.TargetType, RiskLevel: normalizedThreatRiskLevel(row.RiskLevel, row.RiskIndex),
				RiskIndex: row.RiskIndex, Grade: row.Grade, Verdict: row.Verdict, Recommendation: row.Recommendation,
				Source: row.Source, ObservedAt: row.ObservedAt.Format(time.RFC3339), Evidence: append([]string{}, row.Evidence...),
			})
		}
	}

	keys := make([]string, 0, len(subjects))
	for key := range subjects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	findings := []transactionFirewallFinding{}
	for _, key := range keys {
		subject := subjects[key]
		sort.Strings(subject.Modules)
		analysis.Subjects = append(analysis.Subjects, *subject)
		analysis.SubjectsMatched++
		if riskRank(subject.HighestRiskLevel, subject.HighestRiskIndex) > riskRank(analysis.HighestRiskLevel, analysis.HighestRiskIndex) {
			analysis.HighestRiskLevel = subject.HighestRiskLevel
			analysis.HighestRiskIndex = subject.HighestRiskIndex
		}
		if finding, ok := transactionGuardThreatFinding(*subject); ok {
			findings = append(findings, finding)
		}
	}
	if analysis.SubjectsMatched > 0 {
		analysis.Status = "matches_observed"
	}
	return analysis, uniqueGuardV3Findings(findings)
}

func transactionGuardThreatFinding(subject transactionGuardThreatSubject) (transactionFirewallFinding, bool) {
	level := normalizedThreatRiskLevel(subject.HighestRiskLevel, subject.HighestRiskIndex)
	score := 0
	severity := level
	switch level {
	case "critical":
		score = 75
	case "high":
		score = 50
	case "medium":
		score = 25
	default:
		return transactionFirewallFinding{}, false
	}
	detail := ""
	if len(subject.Matches) > 0 {
		detail = strings.TrimSpace(subject.Matches[0].Verdict)
		if recommendation := strings.TrimSpace(subject.Matches[0].Recommendation); recommendation != "" {
			detail = strings.TrimSpace(detail + "; recommendation=" + recommendation)
		}
	}
	return transactionFirewallFinding{
		Code: "historical_risk_match_" + strings.ToLower(subject.Address), Severity: severity,
		Title:    "Signed historical risk verdict matched a transaction subject",
		Evidence: compactGuardV3Evidence(fmt.Sprintf("address=%s roles=%s risk=%s/%d verdicts=%d %s", subject.Address, strings.Join(subject.Roles, ","), level, subject.HighestRiskIndex, subject.SignedVerdictCount, detail)),
		Score:    score,
	}, true
}

func transactionGuardThreatUnavailableFindings(required bool, evidence string) []transactionFirewallFinding {
	severity := "info"
	if required {
		severity = "high"
	}
	return []transactionFirewallFinding{{
		Code: "transaction_threat_history_unavailable", Severity: severity,
		Title:    "Transaction subject threat history is unavailable",
		Evidence: compactGuardV3Evidence(evidence), Score: 0,
	}}
}

func transactionGuardThreatEvidenceStrings(raw []byte) []string {
	if len(raw) == 0 {
		return []string{}
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return []string{}
	}
	out := []string{}
	appendValue := func(item any) {
		text := strings.TrimSpace(fmt.Sprint(item))
		if text != "" && text != "<nil>" && len(out) < 5 {
			out = append(out, compactGuardV3Evidence(text))
		}
	}
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			switch row := item.(type) {
			case string:
				appendValue(row)
			case map[string]any:
				appendValue(firstNonEmptyString(fmt.Sprint(row["summary"]), fmt.Sprint(row["title"]), fmt.Sprint(row["evidence"]), fmt.Sprint(row["code"])))
			default:
				appendValue(row)
			}
		}
	case map[string]any:
		appendValue(firstNonEmptyString(fmt.Sprint(typed["summary"]), fmt.Sprint(typed["title"]), fmt.Sprint(typed["evidence"])))
	case string:
		appendValue(typed)
	}
	return out
}

func normalizedThreatRiskLevel(level string, index int) string {
	level = strings.ToLower(strings.TrimSpace(level))
	switch level {
	case "critical", "high", "medium", "low":
		return level
	}
	switch {
	case index >= 75:
		return "critical"
	case index >= 50:
		return "high"
	case index >= 25:
		return "medium"
	default:
		return "low"
	}
}

func riskRank(level string, index int) int {
	base := 0
	switch normalizedThreatRiskLevel(level, index) {
	case "critical":
		base = 400
	case "high":
		base = 300
	case "medium":
		base = 200
	case "low":
		base = 100
	}
	return base + index
}

func containsGuardString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
