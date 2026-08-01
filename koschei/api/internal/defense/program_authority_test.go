package defense

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"
)

type programAuthorityTestRPC struct {
	programID          string
	programDataAddress string
	programHeader      []byte
	programDataHeader  []byte
	calls              int
}

func (f *programAuthorityTestRPC) Call(_ context.Context, _ string, _ string, params any, target any, _ time.Duration) error {
	f.calls++
	address := params.([]any)[0].(string)
	data := f.programHeader
	if address == f.programDataAddress {
		data = f.programDataHeader
	}
	payload := map[string]any{
		"context": map[string]any{"slot": 900},
		"value": map[string]any{
			"data":       []string{base64.StdEncoding.EncodeToString(data), "base64"},
			"executable": true, "owner": UpgradeableLoaderID, "space": len(data),
		},
	}
	raw, _ := json.Marshal(payload)
	return json.Unmarshal(raw, target)
}

func TestInspectProgramAuthorityReadsOnlyMetadataHeaders(t *testing.T) {
	programDataBytes := make([]byte, 32)
	for i := range programDataBytes {
		programDataBytes[i] = 7
	}
	programDataAddress := base58Encode(programDataBytes)
	programHeader := make([]byte, 36)
	binary.LittleEndian.PutUint32(programHeader[:4], 2)
	copy(programHeader[4:], programDataBytes)
	programDataHeader := make([]byte, 45)
	binary.LittleEndian.PutUint32(programDataHeader[:4], 3)
	binary.LittleEndian.PutUint64(programDataHeader[4:12], 12345)
	programDataHeader[12] = 1
	for i := 13; i < 45; i++ {
		programDataHeader[i] = 9
	}
	rpc := &programAuthorityTestRPC{
		programID: "Program111111111111111111111111111111111", programDataAddress: programDataAddress,
		programHeader: programHeader, programDataHeader: programDataHeader,
	}
	result, err := InspectProgramAuthority(context.Background(), rpc, DeploymentResolveInput{ProgramID: rpc.programID, Network: "solana-mainnet"})
	if err != nil {
		t.Fatalf("inspect authority: %v", err)
	}
	if rpc.calls != 2 {
		t.Fatalf("expected two metadata reads, got %d", rpc.calls)
	}
	if result.DeploymentSlot != 12345 || !result.UpgradeAuthorityOpen || result.UpgradeAuthority == "" || result.Immutable {
		t.Fatalf("unexpected authority snapshot: %+v", result)
	}
	if result.Status != "upgrade_authority_open" {
		t.Fatalf("unexpected status %q", result.Status)
	}
}

func TestParseUpgradeableProgramDataHeaderImmutable(t *testing.T) {
	header := make([]byte, 45)
	binary.LittleEndian.PutUint32(header[:4], 3)
	binary.LittleEndian.PutUint64(header[4:12], 77)
	header[12] = 0
	slot, authority, err := parseUpgradeableProgramDataHeader(header)
	if err != nil || slot != 77 || authority != "" {
		t.Fatalf("unexpected immutable header result slot=%d authority=%q err=%v", slot, authority, err)
	}
}
