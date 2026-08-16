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

func (s Supervisor) Handle(ctx context.Context, event RuntimeEvent) (RuntimeDecision, error) {
	decision := EvaluateRuntimeEvent(s.Policy, s.ObservedArtifactSHA256, event)

	var auditErr error
	if s.Audit != nil {
		auditErr = s.Audit.RecordRuntimeDecision(ctx, s.WorkloadID, event, decision)
	} else if decision.Action != RuntimeAllow && !s.ObserveOnly {
		auditErr = fmt.Errorf("runtime %s requires an audit sink", decision.Action)
	}

	if s.ObserveOnly {
		if auditErr != nil { return decision, fmt.Errorf("record runtime decision: %w", auditErr) }
		return decision, nil
	}

	if s.KillOnly && decision.Action == RuntimeDeny {
		killDecision := RuntimeDecision{Action: RuntimeKill, RuleID: decision.RuleID, Description: "kill-only collector escalated violation to workload termination: " + decision.Description}
		if s.Enforcer == nil { return killDecision, fmt.Errorf("kill-only enforcement requires an enforcer") }
		if err := s.Enforcer.Kill(ctx, s.WorkloadID, killDecision); err != nil { return killDecision, fmt.Errorf("enforce kill-only termination: %w", err) }
		if auditErr != nil { return killDecision, fmt.Errorf("workload killed but audit failed: %w", auditErr) }
		return killDecision, nil
	}

	switch decision.Action {
	case RuntimeAllow:
		if auditErr != nil { return decision, fmt.Errorf("record runtime decision: %w", auditErr) }
		return decision, nil
	case RuntimeDeny:
		if s.Enforcer == nil { return decision, fmt.Errorf("runtime deny requires an enforcer") }
		denyErr := s.Enforcer.Deny(ctx, s.WorkloadID, event, decision)
		if denyErr != nil || auditErr != nil {
			killDecision := RuntimeDecision{Action: RuntimeKill, RuleID: "NS-RT-ENF-001", Description: "deny/audit failure escalated to workload termination"}
			killErr := s.Enforcer.Kill(ctx, s.WorkloadID, killDecision)
			if killErr != nil { return decision, fmt.Errorf("deny/audit failure and kill escalation failed: deny=%v audit=%v kill=%w", denyErr, auditErr, killErr) }
			return killDecision, fmt.Errorf("deny/audit failure escalated to kill: deny=%v audit=%v", denyErr, auditErr)
		}
		return decision, nil
	case RuntimeKill:
		if s.Enforcer == nil { return decision, fmt.Errorf("runtime kill requires an enforcer") }
		if err := s.Enforcer.Kill(ctx, s.WorkloadID, decision); err != nil { return decision, fmt.Errorf("enforce runtime kill: %w", err) }
		if auditErr != nil { return decision, fmt.Errorf("workload killed but audit failed: %w", auditErr) }
		return decision, nil
	default:
		return decision, fmt.Errorf("unsupported runtime action %q", decision.Action)
	}
}
