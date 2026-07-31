package services

import (
	"context"
	"fmt"
	"strings"
)

type SolanaSimulationResult struct {
	Context struct {
		Slot int64 `json:"slot"`
	} `json:"context"`
	Value SolanaSimulationValue `json:"value"`
}

type SolanaInnerInstruction struct {
	ProgramIDIndex int   `json:"programIdIndex"`
	Accounts       []int `json:"accounts"`
	Data           string `json:"data"`
	StackHeight    *int  `json:"stackHeight,omitempty"`
}

type SolanaInnerInstructionGroup struct {
	Index        int                      `json:"index"`
	Instructions []SolanaInnerInstruction `json:"instructions"`
}

type SolanaSimulationValue struct {
	Err                  any                           `json:"err"`
	Logs                 []string                      `json:"logs"`
	Accounts             any                           `json:"accounts"`
	UnitsConsumed        *int64                        `json:"unitsConsumed"`
	ReturnData           any                           `json:"returnData"`
	InnerInstructions    []SolanaInnerInstructionGroup `json:"innerInstructions"`
	ReplacementBlockhash any                           `json:"replacementBlockhash"`
}

func SolanaSimulateTransaction(ctx context.Context, rpcURL, transaction, encoding string) (SolanaSimulationResult, error) {
	rpcURL = resolvedSolanaRPCURL(rpcURL)
	transaction = strings.TrimSpace(transaction)
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	if rpcURL == "" {
		return SolanaSimulationResult{}, fmt.Errorf("solana rpc url is empty")
	}
	if transaction == "" {
		return SolanaSimulationResult{}, fmt.Errorf("serialized transaction is empty")
	}
	if encoding == "" {
		encoding = "base64"
	}
	if encoding != "base64" {
		return SolanaSimulationResult{}, fmt.Errorf("unsupported transaction encoding: %s", encoding)
	}

	config := map[string]any{
		"encoding":               encoding,
		"commitment":             "processed",
		"sigVerify":              false,
		"replaceRecentBlockhash": true,
		"innerInstructions":      true,
	}
	return solanaRPCDo[SolanaSimulationResult](ctx, rpcURL, "simulateTransaction", []any{transaction, config})
}
