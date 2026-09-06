package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type customerARVISChatRequest struct {
	Target   string `json:"target"`
	Network  string `json:"network"`
	Question string `json:"question"`
}

type customerARVISChatEvidence struct {
	ID                 string `json:"id,omitempty"`
	Relation           string `json:"relation"`
	CounterpartKind    string `json:"counterpart_kind,omitempty"`
	CounterpartID      string `json:"counterpart_id,omitempty"`
	VerificationStatus string `json:"verification_status"`
	Source             string `json:"source"`
	Signature          string `json:"signature,omitempty"`
	Slot               int64  `json:"slot,omitempty"`
}

func customerARVISChatEvidenceLines(items []services.ActorDefenseEvidenceRecord, limit int) []customerARVISChatEvidence {
	if limit <= 0 || limit > 20 {
		limit = 8
	}
	out := make([]customerARVISChatEvidence, 0, limit)
	for _, item := range items {
		if len(out) >= limit {
			break
		}
		out = append(out, customerARVISChatEvidence{
			ID:                 strings.TrimSpace(item.ID),
			Relation:           strings.TrimSpace(item.Relation),
			CounterpartKind:    strings.TrimSpace(item.CounterpartKind),
			CounterpartID:      strings.TrimSpace(item.CounterpartID),
			VerificationStatus: strings.TrimSpace(item.VerificationStatus),
			Source:             strings.TrimSpace(item.Source),
			Signature:          strings.TrimSpace(item.Signature),
			Slot:               item.Slot,
		})
	}
	return out
}

func customerARVISWalletAnswer(result customerWalletInvestigationResult) string {
	verified := 0
	observed := 0
	for _, item := range result.Dossier.Evidence {
		switch strings.ToLower(strings.TrimSpace(item.VerificationStatus)) {
		case "verified":
			verified++
		case "observed":
			observed++
		}
	}
	if len(result.Dossier.Evidence) == 0 {
		return "ARVIS wallet investigation completed, but no direct evidence record was available in this observation window. Missing evidence is not treated as a safe finding."
	}
	return fmt.Sprintf("ARVIS found %d evidence records for this wallet (%d verified, %d observed). The response is evidence-backed only; relationships are not treated as identity or wrongdoing claims.", len(result.Dossier.Evidence), verified, observed)
}

func customerARVISTokenAnswer(assembly unifiedInvestigationAssembly) string {
	verdict := assembly.UnifiedVerdict
	if strings.TrimSpace(verdict.Grade) == "" {
		return "ARVIS assembled the token investigation, but no deterministic grade was published from the available evidence. Missing or bounded evidence is not treated as safe."
	}
	return fmt.Sprintf("ARVIS deterministic verdict: grade %s, %s. Triggered rules: %d. This chat does not create a second verdict; it exposes the existing investigation and its evidence.", verdict.Grade, verdict.Verdict, len(verdict.TriggeredRules))
}

func (h *Handler) CustomerARVISChat(w http.ResponseWriter, r *http.Request) {
	var req customerARVISChatRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid_request"})
		return
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "target_required"})
		return
	}
	network := strings.TrimSpace(req.Network)
	if network == "" {
		network = "solana-mainnet"
	}
	question := strings.TrimSpace(req.Question)
	if question == "" {
		question = "What did ARVIS find?"
	}

	classification := classifyRadarTarget(r.Context(), target)
	ctx, cancel := context.WithTimeout(r.Context(), 170*time.Second)
	defer cancel()

	base := map[string]any{
		"ok":                    true,
		"schema_version":        "koschei-arvis-customer-chat-v1",
		"mode":                  "evidence_grounded",
		"target":                target,
		"network":               network,
		"question":              question,
		"target_classification": classification,
		"policy": map[string]any{
			"arvis_is_authoritative":             true,
			"chat_cannot_create_verdict":          true,
			"no_evidence_no_claim":                true,
			"missing_evidence_is_not_safe":        true,
			"relationship_is_not_identity_claim":  true,
			"historical_memory_is_context_only":   true,
		},
	}

	if radarTargetWalletInvestigationAllowed(classification) && (classification.Type == radarTargetWallet || classification.Type == radarTargetTokenAccount) {
		result, err := h.runCustomerWalletInvestigation(ctx, target, network, classification)
		if err != nil {
			writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "ARVIS wallet investigation could not be assembled")
			return
		}
		base["investigation_kind"] = "wallet_intelligence"
		base["answer"] = customerARVISWalletAnswer(result)
		base["status"] = customerWalletInvestigationStatus(result)
		base["evidence"] = customerARVISChatEvidenceLines(result.Dossier.Evidence, 8)
		base["evidence_count"] = len(result.Dossier.Evidence)
		base["funding_origin"] = result.FundingOrigin
		base["rule_verdict"] = result.RuleVerdict
		base["historical_memory"] = result.HistoricalMemory
		base["investigation"] = customerWalletInvestigationEnvelope(result, false)
		writeJSON(w, http.StatusOK, base)
		return
	}

	if classification.Type == radarTargetTokenMint {
		assembly := h.buildUnifiedInvestigationReport(ctx, target, network, "customer_arvis_chat")
		base["investigation_kind"] = "token_intelligence"
		base["answer"] = customerARVISTokenAnswer(assembly)
		base["status"] = "ready"
		base["evidence"] = customerARVISChatEvidenceLines(assembly.CombinedEvidence, 8)
		base["evidence_count"] = len(assembly.CombinedEvidence)
		base["rule_verdict"] = assembly.UnifiedVerdict
		base["threat"] = assembly.Threat
		base["investigation"] = assembly.Report
		writeJSON(w, http.StatusOK, base)
		return
	}

	writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
		"ok": false, "error": "unsupported_chat_target", "target": target,
		"target_classification": classification,
		"message": "ARVIS Customer Chat v1 currently supports Solana wallet/token-account targets and token mints. Unsupported targets are not reclassified as safe.",
	})
}
