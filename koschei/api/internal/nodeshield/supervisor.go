package nodeshield

import (
	"context"
	"fmt"
)

type RuntimeEnforcer interface {
	Deny(ctx context.Context, workloadID string, event RuntimeEvent, decision RuntimeDecision) error
	Kill(ctx context.Context, workloadID string, decision RuntimeDecision) error
}

type RuntimeAuditSink interface {
	RecordRuntimeDecision(ctx context.Context, workloadID string, event RuntimeEvent, decision RuntimeDecision) error
}

type Supervisor struct {
	WorkloadID             string
	ObservedArtifactSHA256 string
	Policy                 RuntimePolicy
	Enforcer               RuntimeEnforcer
	Audit                  RuntimeAuditSink
	ObserveOnly            bool
	KillOnly               bool
}

func (s Supervisor) audit(ctx context.Context, event RuntimeEvent, decision RuntimeDecision) error {
	if s.Audit == nil { return fmt.Errorf("runtime %s requires an audit sink", decision.Action) }
	if err := s.Audit.RecordRuntimeDecision(ctx, s.WorkloadID, event, decision); err != nil { return fmt.Errorf("record runtime decision: %w", err) }
	return nil
}

func (s Supervisor) Handle(ctx context.Context, event RuntimeEvent) (RuntimeDecision, error) {
	decision := EvaluateRuntimeEvent(s.Policy, s.ObservedArtifactSHA256, event)

	if s.ObserveOnly {
		if err := s.audit(ctx, event, decision); err != nil { return decision, err }
		return decision, nil
	}

	if s.KillOnly && decision.Action == RuntimeDeny {
		decision = RuntimeDecision{Action: RuntimeKill, RuleID: decision.RuleID, Description: "kill-only collector escalated violation to workload termination: " + decision.Description}
	}

	switch decision.Action {
	case RuntimeAllow:
		if s.Audit != nil {
			if err := s.Audit.RecordRuntimeDecision(ctx, s.WorkloadID, event, decision); err != nil { return decision, fmt.Errorf("record runtime decision: %w", err) }
		}
		return decision, nil
	case RuntimeDeny:
		if s.Enforcer == nil { return decision, fmt.Errorf("runtime deny requires an enforcer") }
		if err := s.Enforcer.Deny(ctx, s.WorkloadID, event, decision); err != nil {
			killDecision := RuntimeDecision{Action: RuntimeKill, RuleID: "NS-RT-ENF-001", Description: "operation denial failed and was escalated to workload termination"}
			killErr := s.Enforcer.Kill(ctx, s.WorkloadID, killDecision)
			if killErr != nil { return decision, fmt.Errorf("deny failed and kill escalation failed: deny=%v kill=%w", err, killErr) }
			if auditErr := s.audit(ctx, event, killDecision); auditErr != nil { return killDecision, fmt.Errorf("deny failed; workload killed; audit failed: %w", auditErr) }
			return killDecision, fmt.Errorf("deny failed and workload was killed: %w", err)
		}
		// Audit occurs only after the deny has been enforced. Evidence failure is
		// fail-closed: terminate rather than leave an unaudited protected workload.
		if auditErr := s.audit(ctx, event, decision); auditErr != nil {
			killDecision := RuntimeDecision{Action: RuntimeKill, RuleID: "NS-RT-AUD-001", Description: "audit failure after deny escalated to workload termination"}
			if killErr := s.Enforcer.Kill(ctx, s.WorkloadID, killDecision); killErr != nil { return decision, fmt.Errorf("audit failed after deny and kill escalation failed: audit=%v kill=%w", auditErr, killErr) }
			return killDecision, fmt.Errorf("audit failed after deny; workload killed: %w", auditErr)
		}
		return decision, nil
	case RuntimeKill:
		if s.Enforcer == nil { return decision, fmt.Errorf("runtime kill requires an enforcer") }
		// Containment is deliberately first: a slow or unavailable audit backend
		// must never keep a forbidden workload alive.
		if err := s.Enforcer.Kill(ctx, s.WorkloadID, decision); err != nil { return decision, fmt.Errorf("enforce runtime kill: %w", err) }
		if err := s.audit(ctx, event, decision); err != nil { return decision, fmt.Errorf("workload killed but audit failed: %w", err) }
		return decision, nil
	default:
		return decision, fmt.Errorf("unsupported runtime action %q", decision.Action)
	}
}
