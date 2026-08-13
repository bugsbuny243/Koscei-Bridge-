package handlers

import (
	"context"
	"os"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type CourtNarrativeClient interface {
	ProsecutorOpinion(context.Context, CourtReadOnlyInput, string) (CourtOpinion, error)
	PanelOpinion(context.Context, CourtReadOnlyInput, []CourtOpinion) (CourtPanel, error)
	SeniorOpinion(context.Context, CourtReadOnlyInput, []CourtOpinion, *CourtPanel) (CourtPanel, error)
}

type CourtReadOnlyInput struct {
	Target         string                       `json:"target"`
	Network        string                       `json:"network"`
	SignedVerdict  services.UnifiedRadarVerdict `json:"signed_verdict"`
	VerdictCard    map[string]any               `json:"verdict_card"`
	EvidencePacket map[string]any               `json:"evidence_packet,omitempty"`
}

type CourtOpinion struct {
	Provider    string   `json:"provider,omitempty"`
	Model       string   `json:"model"`
	Stance      string   `json:"stance"`
	Text        string   `json:"text"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	Limitations []string `json:"limitations,omitempty"`
}

type CourtPanel struct {
	Models      []string       `json:"models"`
	Stance      string         `json:"stance"`
	Text        string         `json:"text"`
	Opinions    []CourtOpinion `json:"opinions,omitempty"`
	Limitations []string       `json:"limitations,omitempty"`
}

type courtTierOverrideKey struct{}

type CourtReport struct {
	Status       string         `json:"status"`
	TierApplied  string         `json:"tier_applied"`
	CaseID       string         `json:"case_id,omitempty"`
	Prosecutors  []CourtOpinion `json:"prosecutors,omitempty"`
	Panel        *CourtPanel    `json:"panel,omitempty"`
	Senior       *CourtPanel    `json:"senior,omitempty"`
	Disagreement bool           `json:"disagreement"`
	Authority    string         `json:"authority"`
	Errors       []string       `json:"errors,omitempty"`
	GeneratedAt  time.Time      `json:"generated_at"`
}

func (h *Handler) courtNarrative(ctx context.Context, in CourtReadOnlyInput, requestedExtended bool) *CourtReport {
	if !envBool("KOSCHEI_COURT_ENABLED", false) {
		return nil
	}
	tier := h.courtTier(ctx)
	report := &CourtReport{
		Status:      "skipped",
		TierApplied: tier,
		CaseID:      courtCaseID(in),
		Authority:   "the signed deterministic verdict is final; court output is commentary/explanation",
		Errors:      []string{},
		GeneratedAt: time.Now().UTC(),
	}
	if tier == "free" || tier == "basic" || h == nil || h.CourtClient == nil {
		return report
	}
	if tier != "pro" && tier != "enterprise" {
		return report
	}
	if !envBool("KOSCHEI_COURT_PROSECUTORS_ENABLED", true) {
		return report
	}

	for _, role := range []string{"kimi-k2.6", "minimax-m3"} {
		opinion, err := h.CourtClient.ProsecutorOpinion(ctx, in, role)
		if err != nil {
			report.Errors = append(report.Errors, role+": "+err.Error())
			continue
		}
		report.Prosecutors = append(report.Prosecutors, normalizeCourtOpinion(opinion, role))
	}
	if len(report.Prosecutors) == 0 {
		report.Status = "error"
		return report
	}
	report.Disagreement = prosecutorsDisagree(report.Prosecutors)
	gradeChanging := len(in.SignedVerdict.TriggeredRules) > 0 || strings.TrimSpace(in.SignedVerdict.Grade) != "-"
	panelRan := false
	panelRequired := gradeChanging || report.Disagreement || len(report.Prosecutors) < 2
	if panelRequired && envBool("KOSCHEI_COURT_PANEL_ENABLED", true) {
		panel, err := h.CourtClient.PanelOpinion(ctx, in, report.Prosecutors)
		if err != nil {
			report.Errors = append(report.Errors, "first_instance_panel: "+err.Error())
		} else {
			report.Panel = &panel
			panelRan = true
		}
	}
	if tier == "enterprise" && envBool("KOSCHEI_COURT_SENIOR_ENABLED", true) && (isDF(in.SignedVerdict.Grade) || panelRan || requestedExtended) {
		senior, err := h.CourtClient.SeniorOpinion(ctx, in, report.Prosecutors, report.Panel)
		if err != nil {
			report.Errors = append(report.Errors, "senior_panel: "+err.Error())
		} else {
			report.Senior = &senior
		}
	}
	if len(report.Errors) > 0 {
		report.Status = "partial"
	} else {
		report.Status = "ready"
	}
	return report
}

func (h *Handler) courtTier(ctx context.Context) string {
	if tier, ok := ctx.Value(courtTierOverrideKey{}).(string); ok {
		return normalizeCourtTier(tier)
	}
	if access, ok := planAccessRequestFromContext(ctx); ok {
		return courtTierFromPlan(access.Evaluation.Plan)
	}
	claims, ok := userFromContext(ctx)
	if !ok || h == nil {
		return "free"
	}
	evaluation, err := h.evaluatePlanAccess(ctx, claims.Sub, normalizedClaimEmail(claims))
	if err != nil || !evaluation.Active {
		return "free"
	}
	return courtTierFromPlan(evaluation.Plan)
}

func courtTierFromPlan(plan string) string {
	switch canonicalSaaSPlan(plan) {
	case "starter":
		return "basic"
	case "professional":
		return "pro"
	case "enterprise":
		return "enterprise"
	default:
		return "free"
	}
}

func normalizeCourtTier(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "basic", "pro", "enterprise":
		return strings.ToLower(strings.TrimSpace(t))
	default:
		return "free"
	}
}

func envBool(k string, d bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	if raw == "" {
		return d
	}
	return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
}

func normalizeCourtOpinion(o CourtOpinion, model string) CourtOpinion {
	o.Model = firstNonEmptyString(strings.TrimSpace(o.Model), model)
	o.Stance = normalizeCourtStance(o.Stance)
	o.Text = strings.TrimSpace(o.Text)
	o.EvidenceIDs = courtUniqueStrings(o.EvidenceIDs, 64)
	o.Limitations = courtUniqueStrings(o.Limitations, 32)
	return o
}

func prosecutorsDisagree(p []CourtOpinion) bool {
	if len(p) < 2 {
		return false
	}
	return strings.TrimSpace(p[0].Stance) != strings.TrimSpace(p[1].Stance)
}

func isDF(g string) bool {
	g = strings.ToUpper(strings.TrimSpace(g))
	return g == "D" || g == "F"
}

func courtCaseID(in CourtReadOnlyInput) string {
	signature := strings.TrimSpace(in.SignedVerdict.Signature)
	if signature == "" {
		return ""
	}
	if len(signature) > 18 {
		signature = signature[:18]
	}
	return "ARVIS-" + strings.ToUpper(signature)
}

func (h *Handler) courtScheduledReport(ctx context.Context) *CourtReport {
	if !envBool("KOSCHEI_COURT_ENABLED", false) {
		return nil
	}
	tier := h.courtTier(ctx)
	report := &CourtReport{
		Status:      "skipped",
		TierApplied: tier,
		Authority:   "the signed deterministic verdict is final; court output is commentary/explanation",
		GeneratedAt: time.Now().UTC(),
	}
	if tier == "free" || tier == "basic" || h.CourtClient == nil {
		return report
	}
	report.Status = "scheduled"
	return report
}
