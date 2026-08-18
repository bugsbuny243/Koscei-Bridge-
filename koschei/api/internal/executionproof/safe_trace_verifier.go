package executionproof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

type SafeTraceFrame struct {
	Depth       uint64 `json:"depth"`
	Type        string `json:"type"`
	From        string `json:"from"`
	To          string `json:"to"`
	InputSHA256 string `json:"input_sha256"`
	Value       string `json:"value"`
	Success     bool   `json:"success"`
}

type SafeTraceEvidence struct {
	RootSafe    string           `json:"root_safe"`
	Frames      []SafeTraceFrame `json:"frames"`
	Truncated   bool             `json:"truncated"`
	TraceSHA256 string           `json:"trace_sha256"`
}

type SafeTraceVerifier struct{}

// Verify rejects self-asserted "fully observed" claims. The engine must return
// a canonical call/delegatecall trace whose digest recomputes exactly and whose
// root frame is the Safe itself. Truncated traces fail closed.
func (SafeTraceVerifier) Verify(trace SafeTraceEvidence) bool {
	if !validAddress(trace.RootSafe) || trace.Truncated || len(trace.Frames) == 0 || !validSHA256Text(trace.TraceSHA256) {
		return false
	}
	if trace.Frames[0].Depth != 0 || normalizeAddress(trace.Frames[0].From) != normalizeAddress(trace.RootSafe) || !trace.Frames[0].Success {
		return false
	}
	for i, frame := range trace.Frames {
		kind := strings.ToLower(strings.TrimSpace(frame.Type))
		if kind != "call" && kind != "delegatecall" && kind != "staticcall" && kind != "create" && kind != "create2" {
			return false
		}
		if !validAddress(frame.From) || !validAddress(frame.To) || !validSHA256Text(frame.InputSHA256) {
			return false
		}
		if i > 0 && frame.Depth > trace.Frames[i-1].Depth+1 {
			return false
		}
	}
	return strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(trace.TraceSHA256), "0x"), safeTraceDigest(trace))
}

func safeTraceDigest(trace SafeTraceEvidence) string {
	frames := append([]SafeTraceFrame(nil), trace.Frames...)
	for i := range frames {
		frames[i].Type = strings.ToLower(strings.TrimSpace(frames[i].Type))
		frames[i].From = normalizeAddress(frames[i].From)
		frames[i].To = normalizeAddress(frames[i].To)
		frames[i].InputSHA256 = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(frames[i].InputSHA256), "0x"))
		frames[i].Value = strings.TrimSpace(frames[i].Value)
	}
	payload := struct {
		RootSafe  string           `json:"root_safe"`
		Frames    []SafeTraceFrame `json:"frames"`
		Truncated bool             `json:"truncated"`
	}{
		RootSafe: normalizeAddress(trace.RootSafe),
		Frames: frames,
		Truncated: trace.Truncated,
	}
	encoded, _ := json.Marshal(payload)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func canonicalizeTraceFrames(frames []SafeTraceFrame) []SafeTraceFrame {
	out := append([]SafeTraceFrame(nil), frames...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Depth != out[j].Depth { return out[i].Depth < out[j].Depth }
		if normalizeAddress(out[i].From) != normalizeAddress(out[j].From) { return normalizeAddress(out[i].From) < normalizeAddress(out[j].From) }
		return normalizeAddress(out[i].To) < normalizeAddress(out[j].To)
	})
	return out
}
