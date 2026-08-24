package handlers

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestCollectProgramSecuritySurfaceReportsAuthorityAndAge(t *testing.T) {
	programHeader := make([]byte, 36)
	binary.LittleEndian.PutUint32(programHeader[:4], 2)
	programDataAddress := "11111111111111111111111111111111"
	programDataHeader := make([]byte, 45)
	binary.LittleEndian.PutUint32(programDataHeader[:4], 3)
	binary.LittleEndian.PutUint64(programDataHeader[4:12], 456)
	programDataHeader[12] = 1
	for i := 13; i < 45; i++ {
		programDataHeader[i] = 1
	}
	blockTime := time.Now().UTC().Add(-10 * 24 * time.Hour).Unix()
	rpc := func(_ context.Context, _ string, method string, params any, target any) error {
		switch method {
		case "getAccountInfo":
			address := params.([]any)[0].(string)
			data := programHeader
			if address == programDataAddress {
				data = programDataHeader
			}
			return programSecurityDecodeInto(map[string]any{
				"context": map[string]any{"slot": 999},
				"value": map[string]any{
					"data":       []string{base64.StdEncoding.EncodeToString(data), "base64"},
					"executable": true, "owner": arvisUpgradeableLoaderID, "space": len(data),
				},
			}, target)
		case "getBlockTime":
			return programSecurityDecodeInto(blockTime, target)
		default:
			t.Fatalf("unexpected RPC method %s", method)
			return nil
		}
	}
	result := collectProgramSecuritySurface(context.Background(), rpc, "solana-mainnet", map[string]any{"launch_platform": "pump.fun"}, services.LPControlEvidence{}, services.TokenMarketSnapshot{})
	if !result.Available || result.Status != "complete" || len(result.Programs) != 1 {
		t.Fatalf("unexpected surface: %+v", result)
	}
	item := result.Programs[0]
	if item.ProgramID != programSecurityPumpFun || !item.UpgradeAuthorityOpen || !item.AgeAvailable {
		t.Fatalf("unexpected program evidence: %+v", item)
	}
	if item.LastDeploymentAgeDays < 9.9 || item.LastDeploymentAgeDays > 10.1 {
		t.Fatalf("unexpected age %.2f", item.LastDeploymentAgeDays)
	}
}

func TestProgramSecurityCandidatesDeduplicateProgramRoles(t *testing.T) {
	items := programSecurityCandidates(
		map[string]any{"launch_platform": "pump.fun", "signals": map[string]any{"program_id": programSecurityPumpFun}},
		services.LPControlEvidence{PoolProgram: programSecurityPumpFun}, services.TokenMarketSnapshot{},
	)
	if len(items) != 1 {
		t.Fatalf("expected one deduplicated program, got %+v", items)
	}
}

func TestInspectARVISProgramAuthorityRejectsMalformedLegacyLoaderData(t *testing.T) {
	tests := []struct {
		name string
		data any
	}{
		{name: "missing", data: nil},
		{name: "invalid base64", data: []string{"%%%", "base64"}},
		{name: "wrong encoding", data: []string{base64.StdEncoding.EncodeToString([]byte{0x7f, 'E', 'L', 'F'}), "base58"}},
		{name: "padded encoding", data: []string{base64.StdEncoding.EncodeToString([]byte{0x7f, 'E', 'L', 'F'}), " base64 "}},
		{name: "extra tuple element", data: []string{base64.StdEncoding.EncodeToString([]byte{0x7f, 'E', 'L', 'F'}), "base64", "unexpected"}},
		{name: "empty", data: []string{"", "base64"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rpc := func(_ context.Context, _ string, method string, _ any, target any) error {
				if method != "getAccountInfo" {
					t.Fatalf("unexpected RPC method %s", method)
				}
				return programSecurityDecodeInto(map[string]any{
					"context": map[string]any{"slot": 999},
					"value": map[string]any{
						"data": tt.data, "executable": true, "owner": arvisLegacyLoaderV2ID,
					},
				}, target)
			}

			if _, err := inspectARVISProgramAuthority(context.Background(), rpc, "solana-mainnet", programSecurityPumpFun); err == nil {
				t.Fatal("expected malformed legacy loader evidence to fail closed")
			}
		})
	}
}

func TestInspectARVISProgramAuthorityAcceptsVerifiedLegacyLoaderData(t *testing.T) {
	rpc := func(_ context.Context, _ string, method string, _ any, target any) error {
		if method != "getAccountInfo" {
			t.Fatalf("unexpected RPC method %s", method)
		}
		return programSecurityDecodeInto(map[string]any{
			"context": map[string]any{"slot": 999},
			"value": map[string]any{
				"data":       []string{base64.StdEncoding.EncodeToString([]byte{0x7f, 'E', 'L', 'F'}), "base64"},
				"executable": true, "owner": arvisLegacyLoaderV2ID,
			},
		}, target)
	}

	snapshot, err := inspectARVISProgramAuthority(context.Background(), rpc, "solana-mainnet", programSecurityPumpFun)
	if err != nil {
		t.Fatalf("inspect legacy loader: %v", err)
	}
	if snapshot.Status != "immutable_legacy_loader" || !snapshot.Immutable || snapshot.LoaderKind != "bpf_loader_v2" {
		t.Fatalf("unexpected legacy loader snapshot: %+v", snapshot)
	}
}

func programSecurityDecodeInto(value any, target any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, target)
}
