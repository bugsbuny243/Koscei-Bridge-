package handlers

import (
	"testing"
	"time"
)

func TestBuildTransactionInvestigationReportProjectsExecutionEvidence(t *testing.T) {
	tx := map[string]any{
		"slot":      float64(12345),
		"blockTime": float64(1_700_000_000),
		"transaction": map[string]any{
			"message": map[string]any{
				"accountKeys": []any{
					map[string]any{"pubkey": "Signer111", "signer": true},
					map[string]any{"pubkey": "Receiver111", "signer": false},
					map[string]any{"pubkey": "TokenAccount111", "signer": false},
				},
				"instructions": []any{
					map[string]any{
						"program":   "system",
						"programId": "11111111111111111111111111111111",
						"parsed": map[string]any{
							"type": "transfer",
							"info": map[string]any{"source": "Signer111", "destination": "Receiver111", "lamports": float64(1000)},
						},
					},
				},
			},
		},
		"meta": map[string]any{
			"err":         nil,
			"fee":         float64(5000),
			"preBalances": []any{float64(10000), float64(1000), float64(0)},
			"postBalances": []any{float64(4000), float64(2000), float64(0)},
			"preTokenBalances": []any{
				map[string]any{
					"accountIndex": float64(2),
					"mint":         "Mint111",
					"owner":        "Signer111",
					"uiTokenAmount": map[string]any{"amount": "100", "decimals": float64(0), "uiAmount": float64(100)},
				},
			},
			"postTokenBalances": []any{
				map[string]any{
					"accountIndex": float64(2),
					"mint":         "Mint111",
					"owner":        "Signer111",
					"uiTokenAmount": map[string]any{"amount": "40", "decimals": float64(0), "uiAmount": float64(40)},
				},
			},
			"innerInstructions": []any{
				map[string]any{
					"index": float64(0),
					"instructions": []any{
						map[string]any{
							"program":   "spl-token",
							"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
							"parsed": map[string]any{
								"type": "transferChecked",
								"info": map[string]any{"mint": "Mint111", "source": "TokenAccount111"},
							},
						},
					},
				},
			},
		},
	}

	report := buildTransactionInvestigationReport("Signature111", "solana-mainnet", tx)
	if report.Status != "complete" {
		t.Fatalf("status=%q", report.Status)
	}
	if !report.Succeeded || report.ExecutionError != nil {
		t.Fatalf("unexpected execution state: succeeded=%v err=%v", report.Succeeded, report.ExecutionError)
	}
	if report.Slot != 12345 || report.FeeLamports != 5000 {
		t.Fatalf("slot/fee mismatch: slot=%d fee=%d", report.Slot, report.FeeLamports)
	}
	wantTime := time.Unix(1_700_000_000, 0).UTC()
	if !report.BlockTime.Equal(wantTime) {
		t.Fatalf("block time=%v want=%v", report.BlockTime, wantTime)
	}
	if len(report.Signers) != 1 || report.Signers[0] != "Signer111" {
		t.Fatalf("signers=%v", report.Signers)
	}
	if len(report.Instructions) != 2 || !report.Instructions[1].Inner {
		t.Fatalf("instructions=%+v", report.Instructions)
	}
	if len(report.InvokedPrograms) != 2 {
		t.Fatalf("programs=%v", report.InvokedPrograms)
	}
	if len(report.SOLBalanceDeltas) != 2 {
		t.Fatalf("sol deltas=%+v", report.SOLBalanceDeltas)
	}
	if len(report.TokenBalanceDeltas) != 1 {
		t.Fatalf("token deltas=%+v", report.TokenBalanceDeltas)
	}
	if got := report.TokenBalanceDeltas[0].Delta; got != -60 {
		t.Fatalf("token delta=%v", got)
	}
	if report.RawTransactionSaved {
		t.Fatal("raw transaction must not be marked as durably saved")
	}
	if report.AttributionClaimed {
		t.Fatal("transaction evidence must not claim real-world attribution")
	}
	if len(report.EvidenceRefs) < 8 {
		t.Fatalf("evidence refs too small: %v", report.EvidenceRefs)
	}
	if len(report.EvidenceLimits) < 2 {
		t.Fatalf("evidence limits missing: %v", report.EvidenceLimits)
	}
}

func TestTransactionInvestigationUnsupportedNetworkIsExplicitGap(t *testing.T) {
	h := &Handler{}
	report := h.investigateTransactionSignature(t.Context(), "Signature111", "ethereum-mainnet")
	if report.Status != "unsupported_network" {
		t.Fatalf("status=%q", report.Status)
	}
	if len(report.CollectionGaps) == 0 {
		t.Fatal("unsupported network must be an explicit collection gap")
	}
	if report.Memory.Status != "" {
		t.Fatalf("unsupported request should not attempt durable memory: %+v", report.Memory)
	}
}
