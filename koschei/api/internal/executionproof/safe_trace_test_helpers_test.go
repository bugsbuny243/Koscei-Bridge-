package executionproof

func validSafeTraceFixture(safe, target string) SafeTraceEvidence {
	trace := SafeTraceEvidence{
		RootSafe: safe,
		Frames: []SafeTraceFrame{{
			Depth:       0,
			Type:        "call",
			From:        safe,
			To:          target,
			InputSHA256: "abababababababababababababababababababababababababababababababab",
			Value:       "0",
			Success:     true,
		}},
	}
	trace.TraceSHA256 = safeTraceDigest(trace)
	return trace
}
