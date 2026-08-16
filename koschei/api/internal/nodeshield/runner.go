package nodeshield

import (
	"context"
	"fmt"
)

// RuntimeEventSource emits normalized workload events. Implementations may use
// eBPF/LSM, an OCI runtime hook, a SoloHost-native collector, or another source.
type RuntimeEventSource interface {
	Next(ctx context.Context) (RuntimeEvent, error)
}

// Guard runs a supervised event stream until the source ends, the context is
// cancelled, or an enforcement/audit failure occurs. A KILL decision stops the
// loop after the enforcer has been invoked.
type Guard struct {
	Source     RuntimeEventSource
	Supervisor Supervisor
}

func (g Guard) Run(ctx context.Context) error {
	if g.Source == nil {
		return fmt.Errorf("runtime guard requires an event source")
	}

	for {
		event, err := g.Source.Next(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read runtime event: %w", err)
		}

		decision, err := g.Supervisor.Handle(ctx, event)
		if err != nil {
			return err
		}
		if decision.Action == RuntimeKill {
			return nil
		}
	}
}
