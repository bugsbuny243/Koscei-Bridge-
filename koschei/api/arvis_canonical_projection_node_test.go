package main

import (
	"os/exec"
	"testing"
)

func TestARVISCanonicalProjectionSemanticRegression(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node runtime is unavailable")
	}
	cmd := exec.Command(node, "--test", "public/js/__tests__/arvis-canonical-projection.test.mjs")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("canonical projection semantic regression failed: %v\n%s", err, output)
	}
}
