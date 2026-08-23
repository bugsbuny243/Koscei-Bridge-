package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"koschei/api/internal/defense"
	"koschei/api/internal/defensecollector"
	"koschei/api/internal/executioncontainment"
	"koschei/api/internal/executionproof"
)

const maxInputBytes = 2 << 20

type request struct {
	ObserverRef         string                               `json:"observer_ref"`
	Chain               string                               `json:"chain"`
	Control             defense.DefenseValidationControlV02 `json:"control"`
	CaseRef             string                               `json:"case_ref"`
	CaseKind            string                               `json:"case_kind"`
	TechniqueID         string                               `json:"technique_id"`
	ExecutionMode       string                               `json:"execution_mode"`
	ImpactOffsetMS      *int64                               `json:"impact_offset_ms,omitempty"`
	ObservationWindowMS int64                                `json:"observation_window_ms"`
	ContainmentReceipt  executioncontainment.Receipt         `json:"containment_receipt"`
	ExecutionProof      executionproof.Proof                 `json:"execution_proof"`
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
	execution, err := defense.AdaptExecutionIntegrityCaseV02(defense.DefenseValidationExecutionAdapterInputV02{
		CaseRef:                req.CaseRef,
		CaseKind:               req.CaseKind,
		TechniqueID:            req.TechniqueID,
		ExecutionMode:          req.ExecutionMode,
		ImpactOffsetMS:         req.ImpactOffsetMS,
		ObservationWindowMS:    req.ObservationWindowMS,
		MainnetTransactionSent: false,
		ContainmentReceipt:     req.ContainmentReceipt,
		ExecutionProof:         req.ExecutionProof,
	})
	if err != nil {
		fatal("recompute observed control artifacts: " + err.Error())
	}
	if !execution.ControlSignaled {
		fatal("independent observer did not observe a control signal")
	}
	event, err := defensecollector.SealAlertV04(req.ObserverRef, req.Control, execution, req.Chain, time.Now())
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
