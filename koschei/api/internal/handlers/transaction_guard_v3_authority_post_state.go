package handlers

import (
	"strconv"
	"strings"

	"koschei/api/internal/services"
)

func enrichTransactionGuardV3AuthorityPostState(event *transactionGuardAuthorityEvent, snapshots transactionGuardAuthoritySnapshots) {
	if event == nil {
		return
	}
	address := firstNonEmptyString(event.Account, event.Source, event.Mint)
	postInfo := guardV3AuthorityAccountInfo(address, snapshots.PostOrder, snapshots.Post)
	if postInfo == nil {
		if event.Kind == "revoke" || event.Kind == "approve" || event.Kind == "approve_checked" || event.Kind == "set_authority" {
			event.EvidenceStatus = "decoded_instruction_post_state_unavailable"
		}
		return
	}

	switch event.Kind {
	case "approve", "approve_checked", "revoke":
		snapshot, err := services.SolanaTokenAuthoritySnapshotFromInfo(postInfo)
		if err != nil {
			event.EvidenceStatus = "decoded_instruction_post_state_parse_failed"
			return
		}
		event.PostStateAvailable = true
		if snapshot.HasDelegate {
			event.PostDelegate = guardV3Base58Encode(snapshot.Delegate[:])
		}
		event.PostDelegatedAmountRaw = strconv.FormatUint(snapshot.DelegatedAmount, 10)
		active := snapshot.HasDelegate && snapshot.DelegatedAmount > 0
		if event.Kind != "revoke" {
			active = active && snapshot.Delegate == guardV3AddressArray(event.Delegate)
		}
		event.ActiveAfterSimulation = boolPointer(active)
		event.Persistent = active
		event.EvidenceStatus = "verified_final_simulated_token_account_state"
	case "set_authority":
		if event.AuthorityType == nil {
			return
		}
		switch *event.AuthorityType {
		case 0, 1:
			snapshot, err := services.SolanaMintAuthoritySnapshotFromInfo(postInfo)
			if err != nil {
				event.EvidenceStatus = "decoded_instruction_post_state_parse_failed"
				return
			}
			event.PostStateAvailable = true
			if snapshot.HasMintAuthority {
				event.PostMintAuthority = guardV3Base58Encode(snapshot.MintAuthority[:])
			}
			if snapshot.HasFreezeAuthority {
				event.PostFreezeAuthority = guardV3Base58Encode(snapshot.FreezeAuthority[:])
			}
			actual := event.PostMintAuthority
			if *event.AuthorityType == 1 {
				actual = event.PostFreezeAuthority
			}
			active := guardV3AuthorityMatchesExpected(actual, event.NewAuthority)
			event.ActiveAfterSimulation = boolPointer(active)
			event.Persistent = active && event.NewAuthority != "revoked"
			event.EvidenceStatus = "verified_final_simulated_mint_state"
		case 2, 3:
			snapshot, err := services.SolanaTokenAuthoritySnapshotFromInfo(postInfo)
			if err != nil {
				event.EvidenceStatus = "decoded_instruction_post_state_parse_failed"
				return
			}
			event.PostStateAvailable = true
			event.PostOwner = guardV3Base58Encode(snapshot.Owner[:])
			if snapshot.HasCloseAuthority {
				event.PostCloseAuthority = guardV3Base58Encode(snapshot.CloseAuthority[:])
			}
			actual := event.PostOwner
			if *event.AuthorityType == 3 {
				actual = event.PostCloseAuthority
			}
			active := guardV3AuthorityMatchesExpected(actual, event.NewAuthority)
			event.ActiveAfterSimulation = boolPointer(active)
			event.Persistent = active && event.NewAuthority != "revoked"
			event.EvidenceStatus = "verified_final_simulated_token_account_state"
		default:
			event.EvidenceStatus = "decoded_extension_authority_final_state_not_parsed"
		}
	}
}

func guardV3AuthorityAccountInfo(address string, order []string, values []*services.SolanaAccountInfo) *services.SolanaAccountInfo {
	for index, candidate := range order {
		if candidate == address && index < len(values) {
			return values[index]
		}
	}
	return nil
}

func guardV3AddressArray(address string) [32]byte {
	var out [32]byte
	decoded, err := decodeSolanaPublicKey(address)
	if err == nil {
		copy(out[:], decoded)
	}
	return out
}

func guardV3AuthorityMatchesExpected(actual, expected string) bool {
	actual = strings.TrimSpace(actual)
	expected = strings.TrimSpace(expected)
	if expected == "revoked" {
		return actual == ""
	}
	return actual == expected
}
