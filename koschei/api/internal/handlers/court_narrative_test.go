package handlers

import (
	"context"
	"errors"
	"testing"

	"koschei/api/internal/services"
)

type fakeCourtClient struct {
	prosecutors, panel, senior int
	stances                    []string
	err                        bool
}

func (f *fakeCourtClient) ProsecutorOpinion(ctx context.Context, in CourtReadOnlyInput, model string) (CourtOpinion, error) {
	f.prosecutors++
	if f.err {
		return CourtOpinion{}, errors.New("boom")
	}
	s := "neutral"
	if len(f.stances) >= f.prosecutors {
		s = f.stances[f.prosecutors-1]
	}
	return CourtOpinion{Model: model, Stance: s, Text: model + " narrative"}, nil
}
func (f *fakeCourtClient) PanelOpinion(context.Context, CourtReadOnlyInput, []CourtOpinion) (CourtPanel, error) {
	f.panel++
	if f.err {
		return CourtPanel{}, errors.New("boom")
	}
	return CourtPanel{Models: []string{"qwen", "glm"}, Stance: "neutral", Text: "panel narrative"}, nil
}
func (f *fakeCourtClient) SeniorOpinion(context.Context, CourtReadOnlyInput, []CourtOpinion, *CourtPanel) (CourtPanel, error) {
	f.senior++
	if f.err {
		return CourtPanel{}, errors.New("boom")
	}
	return CourtPanel{Models: []string{"openai", "together-senior"}, Stance: "elevated", Text: "senior commentary"}, nil
}

func courtCtx(plan string) context.Context {
	plan = canonicalSaaSPlan(plan)
	return withPlanAccessRequestContext(context.Background(), planAccessRequestContext{
		Evaluation:  planAccessEvaluation{Active: plan != "", Plan: plan, OutputsTotal: 100, OutputsRemaining: 100, Source: "entitlement"},
		AuthSubject: "sub", Email: "u@example.com",
	})
}
func verdict(grade string, triggered bool) services.UnifiedRadarVerdict {
	v := services.UnifiedRadarVerdict{Grade: grade, Verdict: "test", RulesetVersion: services.UnifiedRadarRulesetVersion, ActorRuleset: services.ActorDefenseRulesetVersion, Signature: "sig", Signed: true}
	if triggered {
		v.TriggeredRules = []services.ActorDefenseRuleHit{{RuleID: "R", EvidenceStatus: "verified", Tier: "compounding"}}
	}
	return v
}
func courtInput(v services.UnifiedRadarVerdict) CourtReadOnlyInput {
	return CourtReadOnlyInput{Target: "mint", Network: "solana-mainnet", SignedVerdict: v, VerdictCard: map[string]any{"grade": v.Grade, "signature": v.Signature}}
}

func TestCourtNonePerformsZeroModelCalls(t *testing.T) {
	t.Setenv("KOSCHEI_COURT_ENABLED", "true")
	c := &fakeCourtClient{}
	h := &Handler{CourtClient: c}
	r := h.courtNarrative(courtCtx(""), courtInput(verdict("-", false)), false)
	if r == nil || c.prosecutors+c.panel+c.senior != 0 {
		t.Fatalf("calls=%d report=%#v", c.prosecutors+c.panel+c.senior, r)
	}
}
func TestCourtProfessionalAgreeingProsecutorsNoTriggerSkipsPanels(t *testing.T) {
	t.Setenv("KOSCHEI_COURT_ENABLED", "true")
	c := &fakeCourtClient{stances: []string{"neutral", "neutral"}}
	r := (&Handler{CourtClient: c}).courtNarrative(courtCtx("professional"), courtInput(verdict("-", false)), false)
	if r.Status != "ready" || r.TierApplied != "professional" || c.prosecutors != 2 || c.panel != 0 || c.senior != 0 || r.Disagreement {
		t.Fatalf("report=%#v calls=%+v", r, c)
	}
}
func TestCourtProfessionalDisagreementInvokesPanelAndSenior(t *testing.T) {
	t.Setenv("KOSCHEI_COURT_ENABLED", "true")
	c := &fakeCourtClient{stances: []string{"elevated", "neutral"}}
	r := (&Handler{CourtClient: c}).courtNarrative(courtCtx("professional"), courtInput(verdict("-", false)), false)
	if !r.Disagreement || c.panel != 1 || c.senior != 1 || r.Senior == nil {
		t.Fatalf("report=%#v calls=%+v", r, c)
	}
}
func TestCourtProfessionalDGradeInvokesSenior(t *testing.T) {
	t.Setenv("KOSCHEI_COURT_ENABLED", "true")
	c := &fakeCourtClient{stances: []string{"neutral", "neutral"}}
	r := (&Handler{CourtClient: c}).courtNarrative(courtCtx("professional"), courtInput(verdict("D", true)), false)
	if c.senior != 1 || r.Senior == nil || r.TierApplied != "professional" {
		t.Fatalf("report=%#v calls=%+v", r, c)
	}
}
func TestCourtRemovedPlanLabelsDoNotReceiveCourtAccess(t *testing.T) {
	for _, removed := range []string{"pro", "basic", "starter", "enterprise", "studio", "builder"} {
		if got := (&Handler{}).courtTier(courtCtx(removed)); got != "none" {
			t.Fatalf("removed plan %s unexpectedly mapped to %q", removed, got)
		}
	}
}
func TestCourtClientErrorPreservesInputVerdict(t *testing.T) {
	t.Setenv("KOSCHEI_COURT_ENABLED", "true")
	v := verdict("B", true)
	c := &fakeCourtClient{err: true}
	r := (&Handler{CourtClient: c}).courtNarrative(courtCtx("professional"), courtInput(v), false)
	if r.Status != "error" || v.Grade != "B" || v.Signature != "sig" {
		t.Fatalf("report=%#v verdict=%#v", r, v)
	}
}
func TestCourtDoesNotChangeDeterministicVerdict(t *testing.T) {
	t.Setenv("KOSCHEI_COURT_ENABLED", "true")
	v := verdict("D", true)
	before := v.Signature + v.Grade
	c := &fakeCourtClient{stances: []string{"elevated", "neutral"}}
	_ = (&Handler{CourtClient: c}).courtNarrative(courtCtx("professional"), courtInput(v), true)
	after := v.Signature + v.Grade
	if before != after {
		t.Fatalf("verdict changed before=%q after=%q", before, after)
	}
}
