package executioncontainment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// ActionArtifact is the exact canonical action material presented to the
// isolated defensive runner. A runner must execute these exact bytes; a digest
// alone is not sufficient because a real backend needs concrete action data.
type ActionArtifact struct {
	Kind      string
	Canonical []byte
}

func (a ActionArtifact) SHA256() string {
	sum := sha256.Sum256(a.Canonical)
	return hex.EncodeToString(sum[:])
}

func (a ActionArtifact) validFor(input CellInput) bool {
	return strings.TrimSpace(a.Kind) != "" &&
		len(a.Canonical) != 0 &&
		equalDigest(a.SHA256(), input.ActionSHA256)
}

// Runner executes a candidate action only inside an isolated defensive runtime
// and returns observed effects. A Runner has no production forwarding authority.
type Runner interface {
	Observe(ctx context.Context, input CellInput, action ActionArtifact) (Observation, error)
}

// EvaluateWithRunner is the orchestration helper for a Web3 execution
// containment cell. Runner absence, cancellation, invalid/mismatched action
// material, timeout, or backend failure becomes UNAVAILABLE and never RELEASE.
func EvaluateWithRunner(ctx context.Context, input CellInput, action ActionArtifact, runner Runner) (Receipt, error) {
	if runner == nil || !action.validFor(input) {
		return Evaluate(input, Observation{BackendAvailable: false})
	}
	if err := ctx.Err(); err != nil {
		return Evaluate(input, Observation{BackendAvailable: false})
	}

	observation, err := runner.Observe(ctx, input, action)
	if err != nil {
		return Evaluate(input, Observation{BackendAvailable: false})
	}
	if err := ctx.Err(); err != nil {
		return Evaluate(input, Observation{BackendAvailable: false})
	}

	return Evaluate(input, observation)
}
