package defense

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ProgramAuthoritySnapshot is the lightweight read-only control-plane view of a
// deployed Solana program. It reads only loader metadata headers and never
// downloads the executable body.
type ProgramAuthoritySnapshot struct {
	ProgramID            string    `json:"program_id"`
	Network              string    `json:"network"`
	Status               string    `json:"status"`
	LoaderID             string    `json:"loader_id"`
	LoaderKind           string    `json:"loader_kind"`
	ProgramDataAddress   string    `json:"programdata_address,omitempty"`
	AccountSlot          uint64    `json:"account_slot"`
	DeploymentSlot       uint64    `json:"deployment_slot,omitempty"`
	UpgradeAuthority     string    `json:"upgrade_authority,omitempty"`
	UpgradeAuthorityOpen bool      `json:"upgrade_authority_open"`
	Immutable            bool      `json:"immutable"`
	Executable           bool      `json:"executable"`
	ObservedAt           time.Time `json:"observed_at"`
	EvidenceRefs         []string  `json:"evidence_refs"`
	Limitations          []string  `json:"limitations"`
}

// InspectProgramAuthority reads only getAccountInfo metadata slices. For an
// upgradeable program, DeploymentSlot is the latest deployment/upgrade slot in
// ProgramData; it is not claimed as the original creation slot.
func InspectProgramAuthority(ctx context.Context, rpc DeploymentRPC, input DeploymentResolveInput) (ProgramAuthoritySnapshot, error) {
	if rpc == nil {
		return ProgramAuthoritySnapshot{}, errors.New("solana rpc unavailable")
	}
	input.ProgramID = strings.TrimSpace(input.ProgramID)
	input.Network = normalizedNetwork(input.Network)
	if input.ProgramID == "" {
		return ProgramAuthoritySnapshot{}, errors.New("program_id is required")
	}
	programAccount, err := getProgramAuthorityAccount(ctx, rpc, input.Network, input.ProgramID, 45)
	if err != nil {
		return ProgramAuthoritySnapshot{}, fmt.Errorf("program account lookup failed: %w", err)
	}
	if programAccount.Value == nil {
		return ProgramAuthoritySnapshot{}, errors.New("program account not found")
	}
	programData, err := decodeRPCAccountData(programAccount)
	if err != nil {
		return ProgramAuthoritySnapshot{}, fmt.Errorf("program account decode failed: %w", err)
	}
	out := ProgramAuthoritySnapshot{
		ProgramID: input.ProgramID, Network: input.Network, LoaderID: programAccount.Value.Owner,
		AccountSlot: programAccount.Context.Slot, Executable: programAccount.Value.Executable,
		ObservedAt: time.Now().UTC(), EvidenceRefs: []string{"rpc:getAccountInfo:" + input.ProgramID}, Limitations: []string{},
	}
	switch programAccount.Value.Owner {
	case UpgradeableLoaderID:
		out.LoaderKind = "bpf_upgradeable_loader"
		programDataAddress, parseErr := parseUpgradeableProgramAccount(programData)
		if parseErr != nil {
			return ProgramAuthoritySnapshot{}, parseErr
		}
		out.ProgramDataAddress = programDataAddress
		programDataAccount, lookupErr := getProgramAuthorityAccount(ctx, rpc, input.Network, programDataAddress, 45)
		if lookupErr != nil {
			return ProgramAuthoritySnapshot{}, fmt.Errorf("programdata lookup failed: %w", lookupErr)
		}
		if programDataAccount.Value == nil || programDataAccount.Value.Owner != UpgradeableLoaderID {
			return ProgramAuthoritySnapshot{}, errors.New("programdata account owner mismatch")
		}
		header, decodeErr := decodeRPCAccountData(programDataAccount)
		if decodeErr != nil {
			return ProgramAuthoritySnapshot{}, fmt.Errorf("programdata decode failed: %w", decodeErr)
		}
		deploymentSlot, authority, headerErr := parseUpgradeableProgramDataHeader(header)
		if headerErr != nil {
			return ProgramAuthoritySnapshot{}, headerErr
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
	case LegacyLoaderV2ID:
		out.LoaderKind = "bpf_loader_v2"
		out.Status = "immutable_legacy_loader"
		out.Immutable = true
		out.Limitations = append(out.Limitations, "Legacy loader metadata does not expose a ProgramData deployment slot or upgrade authority.")
	case LegacyLoaderV1ID:
		out.LoaderKind = "bpf_loader_v1"
		out.Status = "immutable_legacy_loader"
		out.Immutable = true
		out.Limitations = append(out.Limitations, "Legacy loader metadata does not expose a ProgramData deployment slot or upgrade authority.")
	default:
		return ProgramAuthoritySnapshot{}, fmt.Errorf("unsupported program loader: %s", programAccount.Value.Owner)
	}
	return out, nil
}

func getProgramAuthorityAccount(ctx context.Context, rpc DeploymentRPC, network, address string, dataLength int) (rpcAccountInfo, error) {
	var result rpcAccountInfo
	config := map[string]any{
		"encoding": "base64", "commitment": "confirmed",
		"dataSlice": map[string]any{"offset": 0, "length": dataLength},
	}
	err := rpc.Call(ctx, network, "getAccountInfo", []any{address, config}, &result, 20*time.Second)
	return result, err
}

func parseUpgradeableProgramDataHeader(data []byte) (uint64, string, error) {
	if len(data) < 45 || littleEndianUint32(data[:4]) != 3 {
		return 0, "", errors.New("invalid upgradeable ProgramData header")
	}
	slot := littleEndianUint64(data[4:12])
	switch data[12] {
	case 0:
		return slot, "", nil
	case 1:
		return slot, base58Encode(data[13:45]), nil
	default:
		return 0, "", errors.New("invalid upgrade authority option tag")
	}
}

func littleEndianUint32(value []byte) uint32 {
	return uint32(value[0]) | uint32(value[1])<<8 | uint32(value[2])<<16 | uint32(value[3])<<24
}

func littleEndianUint64(value []byte) uint64 {
	return uint64(value[0]) | uint64(value[1])<<8 | uint64(value[2])<<16 | uint64(value[3])<<24 |
		uint64(value[4])<<32 | uint64(value[5])<<40 | uint64(value[6])<<48 | uint64(value[7])<<56
}
