package handlers

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	arvisUpgradeableLoaderID = "BPFLoaderUpgradeab1e11111111111111111111111"
	arvisLegacyLoaderV2ID    = "BPFLoader2111111111111111111111111111111111"
	arvisLegacyLoaderV1ID    = "BPFLoader1111111111111111111111111111111111"
)

type arvisProgramAuthoritySnapshot struct {
	ProgramID            string
	Network              string
	Status               string
	LoaderID             string
	LoaderKind           string
	ProgramDataAddress   string
	AccountSlot          uint64
	DeploymentSlot       uint64
	UpgradeAuthority     string
	UpgradeAuthorityOpen bool
	Immutable            bool
	Executable           bool
	ObservedAt           time.Time
	EvidenceRefs         []string
	Limitations          []string
}

type arvisProgramAuthorityAccount struct {
	Context struct {
		Slot uint64 `json:"slot"`
	} `json:"context"`
	Value *struct {
		Data       []string `json:"data"`
		Executable bool     `json:"executable"`
		Owner      string   `json:"owner"`
		Space      uint64   `json:"space"`
	} `json:"value"`
}

// inspectArvisProgramAuthority is ARVIS-owned, read-only program metadata
// inspection. It reads only loader headers; it does not download executable
// bytecode, mutate chain state, or depend on the removed Defense OS boundary.
func inspectArvisProgramAuthority(ctx context.Context, rpc solanaRPCCall, network, programID string) (arvisProgramAuthoritySnapshot, error) {
	if rpc == nil {
		return arvisProgramAuthoritySnapshot{}, errors.New("solana rpc unavailable")
	}
	programID = strings.TrimSpace(programID)
	network = strings.TrimSpace(network)
	if network == "" {
		network = "solana-mainnet"
	}
	if programID == "" {
		return arvisProgramAuthoritySnapshot{}, errors.New("program_id is required")
	}

	programAccount, err := getArvisProgramAuthorityAccount(ctx, rpc, network, programID, 45)
	if err != nil {
		return arvisProgramAuthoritySnapshot{}, fmt.Errorf("program account lookup failed: %w", err)
	}
	if programAccount.Value == nil {
		return arvisProgramAuthoritySnapshot{}, errors.New("program account not found")
	}
	programData, err := decodeArvisProgramAuthorityAccount(programAccount)
	if err != nil {
		return arvisProgramAuthoritySnapshot{}, fmt.Errorf("program account decode failed: %w", err)
	}

	out := arvisProgramAuthoritySnapshot{
		ProgramID: programID,
		Network: network,
		LoaderID: programAccount.Value.Owner,
		AccountSlot: programAccount.Context.Slot,
		Executable: programAccount.Value.Executable,
		ObservedAt: time.Now().UTC(),
		EvidenceRefs: []string{"rpc:getAccountInfo:" + programID},
		Limitations: []string{},
	}

	switch programAccount.Value.Owner {
	case arvisUpgradeableLoaderID:
		out.LoaderKind = "bpf_upgradeable_loader"
		programDataAddress, parseErr := parseArvisUpgradeableProgramAccount(programData)
		if parseErr != nil {
			return arvisProgramAuthoritySnapshot{}, parseErr
		}
		out.ProgramDataAddress = programDataAddress
		programDataAccount, lookupErr := getArvisProgramAuthorityAccount(ctx, rpc, network, programDataAddress, 45)
		if lookupErr != nil {
			return arvisProgramAuthoritySnapshot{}, fmt.Errorf("programdata lookup failed: %w", lookupErr)
		}
		if programDataAccount.Value == nil || programDataAccount.Value.Owner != arvisUpgradeableLoaderID {
			return arvisProgramAuthoritySnapshot{}, errors.New("programdata account owner mismatch")
		}
		header, decodeErr := decodeArvisProgramAuthorityAccount(programDataAccount)
		if decodeErr != nil {
			return arvisProgramAuthoritySnapshot{}, fmt.Errorf("programdata decode failed: %w", decodeErr)
		}
		deploymentSlot, authority, headerErr := parseArvisUpgradeableProgramDataHeader(header)
		if headerErr != nil {
			return arvisProgramAuthoritySnapshot{}, headerErr
		}
		out.DeploymentSlot = deploymentSlot
		out.UpgradeAuthority = authority
		out.UpgradeAuthorityOpen = authority != ""
		out.Immutable = authority == ""
		if out.UpgradeAuthorityOpen {
			out.Status = "upgrade_authority_open"
		} else {
			out.Status = "immutable_upgradeable_program"
		}
		out.EvidenceRefs = append(out.EvidenceRefs, "rpc:getAccountInfo:"+programDataAddress)
		out.Limitations = append(out.Limitations, "Deployment slot is the latest deployment or upgrade recorded in ProgramData, not proof of the original creation slot.")
	case arvisLegacyLoaderV2ID:
		out.LoaderKind = "bpf_loader_v2"
		out.Status = "immutable_legacy_loader"
		out.Immutable = true
		out.Limitations = append(out.Limitations, "Legacy loader metadata does not expose a ProgramData deployment slot or upgrade authority.")
	case arvisLegacyLoaderV1ID:
		out.LoaderKind = "bpf_loader_v1"
		out.Status = "immutable_legacy_loader"
		out.Immutable = true
		out.Limitations = append(out.Limitations, "Legacy loader metadata does not expose a ProgramData deployment slot or upgrade authority.")
	default:
		return arvisProgramAuthoritySnapshot{}, fmt.Errorf("unsupported program loader: %s", programAccount.Value.Owner)
	}
	return out, nil
}

func getArvisProgramAuthorityAccount(ctx context.Context, rpc solanaRPCCall, network, address string, dataLength int) (arvisProgramAuthorityAccount, error) {
	var result arvisProgramAuthorityAccount
	config := map[string]any{
		"encoding": "base64",
		"commitment": "confirmed",
		"dataSlice": map[string]any{"offset": 0, "length": dataLength},
	}
	err := rpc(ctx, network, "getAccountInfo", []any{address, config}, &result)
	return result, err
}

func decodeArvisProgramAuthorityAccount(account arvisProgramAuthorityAccount) ([]byte, error) {
	if account.Value == nil || len(account.Value.Data) < 2 || !strings.EqualFold(account.Value.Data[1], "base64") {
		return nil, errors.New("account data is not base64 encoded")
	}
	decoded, err := base64.StdEncoding.DecodeString(account.Value.Data[0])
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func parseArvisUpgradeableProgramAccount(data []byte) (string, error) {
	if len(data) < 36 || binary.LittleEndian.Uint32(data[:4]) != 2 {
		return "", errors.New("invalid upgradeable Program account state")
	}
	return base58Encode(data[4:36]), nil
}

func parseArvisUpgradeableProgramDataHeader(data []byte) (uint64, string, error) {
	if len(data) < 45 || binary.LittleEndian.Uint32(data[:4]) != 3 {
		return 0, "", errors.New("invalid upgradeable ProgramData header")
	}
	slot := binary.LittleEndian.Uint64(data[4:12])
	switch data[12] {
	case 0:
		return slot, "", nil
	case 1:
		return slot, base58Encode(data[13:45]), nil
	default:
		return 0, "", errors.New("invalid upgrade authority option tag")
	}
}
