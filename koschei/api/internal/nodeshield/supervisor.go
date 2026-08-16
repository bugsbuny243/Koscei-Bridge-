package nodeshield

import (
	"context"
	"fmt"
)

// RuntimeEnforcer applies a Node Shield runtime decision to the underlying
// execution platform. Platform adapters should implement only narrowly scoped
// actions; the policy engine remains platform-neutral.
type RuntimeEnforcer interface {
	Deny(ctx context.Context, workloadID string, event RuntimeEvent, decision RuntimeDecision) error
	Kill(ctx context.Context, workloadID string, decision RuntimeDecision) error
}

// RuntimeAuditSink receives every decision before enforcement is attempted.
// Audit failure is treated as fatal for deny/kill decisions so a blocked action
// cannot become invisible to the evidence trail.
type RuntimeAuditSink interface {
	RecordRuntimeDecision(ctx context.Context, workloadID string, event RuntimeEvent, decision RuntimeDecision) error
}

// Supervisor binds one approved artifact and runtime policy to a concrete
// workload instance. It does not collect events itself; collectors normalize
// platform-specific telemetry into RuntimeEvent and call Handle.
type Supervisor struct {
	WorkloadID             string
	ObservedArtifactSHA256 string
	Policy                 RuntimePolicy
	Enforcer               RuntimeEnforcer
	Audit                  RuntimeAuditSink
}

// Handle evaluates and enforces one runtime event. ALLOW returns without a
// platform mutation. DENY and KILL are fail-closed: missing enforcement or
// missing audit support returns an error rather than silently continuing.
func (s Supervisor) Handle(ctx context.Context, event RuntimeEvent) (RuntimeDecision, error) {
	decision := EvaluateRuntimeEvent(s.Policy, s.ObservedArtifactSHA256, event)

	if s.Audit != nil {
		if err := s.Audit.RecordRuntimeDecision(ctx, s.WorkloadID, event, decision); err != nil {
			if decision.Action != RuntimeAllow {
				return decision, fmt.Errorf("record runtime decision: %w", err)
			}
		}
	} else if decision.Action != RuntimeAllow {
		return decision, fmt.Errorf("runtime %s requires an audit sink", decision.Action)
	}

	switch decision.Action {
	case RuntimeAllow:
		return decision, nil
	case RuntimeDeny:
		if s.Enforcer == nil {
			return decision, fmt.Errorf("runtime deny requires an enforcer")
		}
		if err := s.Enforcer.Deny(ctx, s.WorkloadID, event, decision); err != nil {
			return decision, fmt.Errorf("enforce runtime deny: %w", err)
		}
		return decision, nil
	case RuntimeKill:
		if s.Enforcer == nil {
			return decision, fmt.Errorf("runtime kill requires an enforcer")
		}
		if err := s.Enforcer.Kill(ctx, s.WorkloadID, decision); err != nil {
			return decision, fmt.Errorf("enforce runtime kill: %w", err)
		}
		return decision, nil
	default:
		return decision, fmt.Errorf("unsupported runtime action %q", decision.Action)
	}
}
