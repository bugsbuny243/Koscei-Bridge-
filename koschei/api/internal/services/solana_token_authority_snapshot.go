package services

import (
	"encoding/binary"
	"fmt"
)

const minimumTokenMintSize = 82

type SolanaTokenAuthoritySnapshot struct {
	Mint               [32]byte
	Owner              [32]byte
	Amount             uint64
	State              uint8
	HasDelegate        bool
	Delegate           [32]byte
	DelegatedAmount    uint64
	HasCloseAuthority  bool
	CloseAuthority     [32]byte
}

type SolanaMintAuthoritySnapshot struct {
	HasMintAuthority   bool
	MintAuthority      [32]byte
	Supply             uint64
	Decimals           uint8
	Initialized        bool
	HasFreezeAuthority bool
	FreezeAuthority    [32]byte
}

func SolanaTokenAuthoritySnapshotFromInfo(info *SolanaAccountInfo) (SolanaTokenAuthoritySnapshot, error) {
	var snapshot SolanaTokenAuthoritySnapshot
	if info == nil {
		return snapshot, fmt.Errorf("token account is unavailable")
	}
	if !isGuardTokenProgram(info.Owner) {
		return snapshot, fmt.Errorf("account is not owned by an SPL token program")
	}
	data, err := solanaAccountDataBytes(info.Data)
	if err != nil {
		return snapshot, err
	}
	if len(data) < minimumTokenAccountSize {
		return snapshot, fmt.Errorf("token account data is too short")
	}
	copy(snapshot.Mint[:], data[:32])
	copy(snapshot.Owner[:], data[32:64])
	snapshot.Amount = binary.LittleEndian.Uint64(data[64:72])
	snapshot.State = data[108]
	if present, key, err := unpackGuardCOptionPubkey(data[72:108]); err != nil {
		return snapshot, fmt.Errorf("decode delegate: %w", err)
	} else {
		snapshot.HasDelegate = present
		snapshot.Delegate = key
	}
	snapshot.DelegatedAmount = binary.LittleEndian.Uint64(data[121:129])
	if present, key, err := unpackGuardCOptionPubkey(data[129:165]); err != nil {
		return snapshot, fmt.Errorf("decode close authority: %w", err)
	} else {
		snapshot.HasCloseAuthority = present
		snapshot.CloseAuthority = key
	}
	return snapshot, nil
}

func SolanaMintAuthoritySnapshotFromInfo(info *SolanaAccountInfo) (SolanaMintAuthoritySnapshot, error) {
	var snapshot SolanaMintAuthoritySnapshot
	if info == nil {
		return snapshot, fmt.Errorf("mint account is unavailable")
	}
	if !isGuardTokenProgram(info.Owner) {
		return snapshot, fmt.Errorf("account is not owned by an SPL token program")
	}
	data, err := solanaAccountDataBytes(info.Data)
	if err != nil {
		return snapshot, err
	}
	if len(data) < minimumTokenMintSize {
		return snapshot, fmt.Errorf("mint account data is too short")
	}
	if present, key, err := unpackGuardCOptionPubkey(data[:36]); err != nil {
		return snapshot, fmt.Errorf("decode mint authority: %w", err)
	} else {
		snapshot.HasMintAuthority = present
		snapshot.MintAuthority = key
	}
	snapshot.Supply = binary.LittleEndian.Uint64(data[36:44])
	snapshot.Decimals = data[44]
	snapshot.Initialized = data[45] == 1
	if present, key, err := unpackGuardCOptionPubkey(data[46:82]); err != nil {
		return snapshot, fmt.Errorf("decode freeze authority: %w", err)
	} else {
		snapshot.HasFreezeAuthority = present
		snapshot.FreezeAuthority = key
	}
	return snapshot, nil
}

func unpackGuardCOptionPubkey(data []byte) (bool, [32]byte, error) {
	var key [32]byte
	if len(data) < 36 {
		return false, key, fmt.Errorf("COption pubkey is truncated")
	}
	switch binary.LittleEndian.Uint32(data[:4]) {
	case 0:
		return false, key, nil
	case 1:
		copy(key[:], data[4:36])
		return true, key, nil
	default:
		return false, key, fmt.Errorf("invalid COption pubkey tag")
	}
}
