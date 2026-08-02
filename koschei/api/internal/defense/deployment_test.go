package defense

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"
)

type fakeDeploymentRPC struct {
	accounts map[string]rpcAccountInfo
}

func (f fakeDeploymentRPC) Call(_ context.Context, _ string, _ string, params any, target any, _ time.Duration) error {
	values := params.([]any)
	address := values[0].(string)
	encoded, _ := json.Marshal(f.accounts[address])
	return json.Unmarshal(encoded, target)
}

func accountInfo(slot uint64, owner string, executable bool, data []byte) rpcAccountInfo {
	var result rpcAccountInfo
	result.Context.Slot = slot
	result.Value = &struct {
		Data       []string `json:"data"`
		Executable bool     `json:"executable"`
		Owner      string   `json:"owner"`
		Space      uint64   `json:"space"`
	}{
		Data:       []string{base64.StdEncoding.EncodeToString(data), "base64"},
		Executable: executable,
		Owner:      owner,
		Space:      uint64(len(data)),
	}
	return result
}

func TestInspectUpgradeableProgramDeployment(t *testing.T) {
	programID := "Program111111111111111111111111111111111"
	programDataKey := make([]byte, 32)
	authorityKey := make([]byte, 32)
	for i := range programDataKey {
		programDataKey[i] = byte(i + 1)
		authorityKey[i] = byte(100 + i)
	}
	programDataAddress := base58Encode(programDataKey)
	authorityAddress := base58Encode(authorityKey)

	programState := make([]byte, 36)
	binary.LittleEndian.PutUint32(programState[:4], 2)
	copy(programState[4:], programDataKey)

	executable := []byte{0x7f, 'E', 'L', 'F', 1, 2, 3, 0, 0, 0}
	programDataState := make([]byte, 45+len(executable))
	binary.LittleEndian.PutUint32(programDataState[:4], 3)
	binary.LittleEndian.PutUint64(programDataState[4:12], 987654)
	programDataState[12] = 1
	copy(programDataState[13:45], authorityKey)
	copy(programDataState[45:], executable)

	rpc := fakeDeploymentRPC{accounts: map[string]rpcAccountInfo{
		programID:          accountInfo(1234, UpgradeableLoaderID, true, programState),
		programDataAddress: accountInfo(1234, UpgradeableLoaderID, false, programDataState),
	}}
	result, err := InspectProgramDeployment(context.Background(), rpc, DeploymentResolveInput{ProgramID: programID, Network: "mainnet"})
	if err != nil {
		t.Fatal(err)
	}
	if result.LoaderKind != "bpf_upgradeable_loader" || result.ProgramDataAddress != programDataAddress {
		t.Fatalf("unexpected loader resolution: %+v", result.DeploymentSnapshot)
	}
	if result.UpgradeAuthority != authorityAddress || !result.UpgradeAuthorityOpen {
		t.Fatalf("unexpected authority: %+v", result.DeploymentSnapshot)
	}
	if result.DeploymentSlot != 987654 || result.AccountSlot != 1234 {
		t.Fatalf("unexpected slots: %+v", result.DeploymentSnapshot)
	}
	if result.FullBinarySize != len(executable) || result.CanonicalBinarySize != 7 || result.TrailingZeroBytes != 3 {
		t.Fatalf("unexpected binary sizing: %+v", result.DeploymentSnapshot)
	}
	if result.FullBinaryHash == result.CanonicalBinaryHash {
		t.Fatal("full and canonical hashes should differ when allocation padding exists")
	}
}

func TestInspectLegacyProgramDeployment(t *testing.T) {
	programID := "Legacy1111111111111111111111111111111111"
	bytecode := []byte{0x7f, 'E', 'L', 'F', 9, 8, 7}
	rpc := fakeDeploymentRPC{accounts: map[string]rpcAccountInfo{
		programID: accountInfo(77, LegacyLoaderV2ID, true, bytecode),
	}}
	result, err := InspectProgramDeployment(context.Background(), rpc, DeploymentResolveInput{ProgramID: programID, Network: "solana-mainnet"})
	if err != nil {
		t.Fatal(err)
	}
	if result.LoaderKind != "bpf_loader_v2" || result.UpgradeAuthorityOpen || result.CanonicalBinarySize != len(bytecode) {
		t.Fatalf("unexpected legacy result: %+v", result.DeploymentSnapshot)
	}
}

func TestParseUpgradeableProgramDataRejectsInvalidAuthorityTag(t *testing.T) {
	data := make([]byte, 46)
	binary.LittleEndian.PutUint32(data[:4], 3)
	data[12] = 2
	if _, _, _, err := parseUpgradeableProgramData(data); err == nil {
		t.Fatal("invalid authority option tag was accepted")
	}
}

func TestBase58EncodeLeadingZeros(t *testing.T) {
	zeros := make([]byte, 32)
	if got := base58Encode(zeros); got != "11111111111111111111111111111111" {
		t.Fatalf("unexpected zero pubkey encoding: %q", got)
	}
	if got := base58Encode([]byte{0, 1}); got != "12" {
		t.Fatalf("unexpected leading-zero encoding: %q", got)
	}
}

func TestTrimTrailingZeroPadding(t *testing.T) {
	canonical, padding := trimTrailingZeroPadding([]byte{1, 2, 3, 0, 0})
	if padding != 2 || len(canonical) != 3 || canonical[2] != 3 {
		t.Fatalf("unexpected normalization: %v padding=%d", canonical, padding)
	}
}
