package nodeshield

import (
	"context"
	"fmt"
	"io"
)

type RuntimeEventSource interface { Next(ctx context.Context) (RuntimeEvent, error) }

type Guard struct {
	Source RuntimeEventSource
	Supervisor Supervisor
	RequirePreAction bool
}

func (g Guard) Run(ctx context.Context) error {
	if g.Source == nil { return fmt.Errorf("runtime guard requires an event source") }

	mode := EnforcementObserveOnly
	capsSource, ok := g.Source.(CapabilitySource)
	if !ok {
		if g.RequirePreAction { return fmt.Errorf("pre-action enforcement requires a capability-aware event source") }
	} else {
		caps := capsSource.Capabilities()
		if err := ValidateRuntimeCapabilities(caps, g.RequirePreAction); err != nil { return fmt.Errorf("validate runtime capabilities: %w", err) }
		mode = caps.Mode
	}

	if g.RequirePreAction && g.Supervisor.Enforcer == nil { return fmt.Errorf("pre-action enforcement requires an enforcer") }
	if mode == EnforcementKillOnly && g.Supervisor.Enforcer == nil { return fmt.Errorf("kill-only enforcement requires an enforcer") }
	if mode == EnforcementObserveOnly && g.Supervisor.Audit == nil { return fmt.Errorf("observe-only mode requires an audit sink") }
	g.Supervisor.ObserveOnly = mode == EnforcementObserveOnly
	g.Supervisor.KillOnly = mode == EnforcementKillOnly

	startupDecision := EvaluateRuntimeEvent(g.Supervisor.Policy, g.Supervisor.ObservedArtifactSHA256, RuntimeEvent{})
	if startupDecision.Action == RuntimeKill {
		if g.Supervisor.ObserveOnly {
			if err := g.Supervisor.Audit.RecordRuntimeDecision(ctx, g.Supervisor.WorkloadID, RuntimeEvent{}, startupDecision); err != nil { return fmt.Errorf("record startup artifact mismatch: %w", err) }
			return nil
		}
		if g.Supervisor.Enforcer == nil { return fmt.Errorf("artifact mismatch requires an enforcer") }
		if err := g.Supervisor.Enforcer.Kill(ctx, g.Supervisor.WorkloadID, startupDecision); err != nil { return fmt.Errorf("kill mismatched workload before event loop: %w", err) }
		if g.Supervisor.Audit == nil { return fmt.Errorf("workload killed but startup audit sink is missing") }
		if err := g.Supervisor.Audit.RecordRuntimeDecision(ctx, g.Supervisor.WorkloadID, RuntimeEvent{}, startupDecision); err != nil { return fmt.Errorf("workload killed but startup audit failed: %w", err) }
		return nil
	}

	for {
		event, err := g.Source.Next(ctx)
		if err != nil {
			if ctx.Err() != nil { return ctx.Err() }
			if err == io.EOF { return nil }
			return fmt.Errorf("read runtime event: %w", err)
		}
		decision, err := g.Supervisor.Handle(ctx, event)
		if err != nil { return err }
		if decision.Action == RuntimeKill && !g.Supervisor.ObserveOnly { return nil }
	}
}
