package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"koschei/api/internal/defense"
	"koschei/api/internal/defensecollector"
)

const maxInputBytes = 2 << 20

type request struct {
	ObserverRef string                                          `json:"observer_ref"`
	Chain       string                                          `json:"chain"`
	Control     defense.DefenseValidationControlV02             `json:"control"`
	Execution   defense.DefenseValidationExecutionEvidenceV02   `json:"execution"`
}

func main() {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxInputBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxInputBytes {
		fatal("invalid bounded observer request")
	}
	var req request
	if err := json.Unmarshal(data, &req); err != nil {
		fatal("decode observer request: " + err.Error())
	}
	event, err := defensecollector.SealAlertV04(req.ObserverRef, req.Control, req.Execution, req.Chain, time.Now())
	if err != nil {
		fatal("observe alert: " + err.Error())
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(event); err != nil {
		fatal("encode alert event: " + err.Error())
	}
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
