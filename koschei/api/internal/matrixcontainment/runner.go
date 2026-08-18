package matrixcontainment

import "context"

// Runner executes a candidate action only inside an isolated defensive runtime
// and returns observed effects. A Runner has no production forwarding authority.
type Runner interface {
	Observe(ctx context.Context, input CellInput) (Observation, error)
}

// EvaluateWithRunner is the only orchestration helper for a containment cell.
// Runner absence, cancellation, timeout, or backend failure is represented as
// UNAVAILABLE evidence and therefore can never become RELEASE.
func EvaluateWithRunner(ctx context.Context, input CellInput, runner Runner) (Receipt, error) {
	if runner == nil {
		return Evaluate(input, Observation{BackendAvailable: false})
	}
	if err := ctx.Err(); err != nil {
		return Evaluate(input, Observation{BackendAvailable: false})
	}

	observation, err := runner.Observe(ctx, input)
	if err != nil {
		return Evaluate(input, Observation{BackendAvailable: false})
	}
	if err := ctx.Err(); err != nil {
		return Evaluate(input, Observation{BackendAvailable: false})
	}

	return Evaluate(input, observation)
}
