package handlers

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
)

func decodeTransactionGuardV3AuthorityEvent(instruction transactionGuardAuthorityInstruction) (transactionGuardAuthorityEvent, bool, error) {
	event := transactionGuardAuthorityEvent{
		InstructionSource: instruction.Source, InstructionIndex: instruction.Index, InnerSequence: instruction.InnerSequence,
		ParentProgramID: instruction.ParentProgramID, ProgramID: instruction.ProgramID,
		Scope: "not_applicable", EvidenceStatus: "decoded_instruction",
	}
	data := instruction.Data
	accounts := instruction.Accounts
	if len(data) == 0 {
		return event, false, nil
	}
	switch data[0] {
	case 4:
		if len(data) < 9 || len(accounts) < 3 {
			return event, true, fmt.Errorf("Approve instruction is truncated")
		}
		event.Kind, event.Source, event.Delegate, event.CurrentAuthority = "approve", accounts[0], accounts[1], accounts[2]
		event.Account = event.Source
		event.AmountRaw = strconv.FormatUint(binary.LittleEndian.Uint64(data[1:9]), 10)
		event.Amount = event.AmountRaw
		event.Scope, event.Persistent = "single_token_account_allowance", true
		event.EffectivelyUnlimited = event.AmountRaw == strconv.FormatUint(math.MaxUint64, 10)
		event.Explanation = "The delegate may transfer up to the approved raw token amount until the allowance is spent or revoked."
	case 5:
		if len(accounts) < 2 {
			return event, true, fmt.Errorf("Revoke instruction is truncated")
		}
		event.Kind, event.Source, event.CurrentAuthority = "revoke", accounts[0], accounts[1]
		event.Account, event.Scope = event.Source, "single_token_account_allowance"
		event.Explanation = "The token-account delegate allowance is revoked."
	case 6:
		if len(data) < 3 || len(accounts) < 2 {
			return event, true, fmt.Errorf("SetAuthority instruction is truncated")
		}
		authorityType := int(data[1])
		event.Kind, event.Account, event.CurrentAuthority, event.AuthorityType = "set_authority", accounts[0], accounts[1], &authorityType
		event.AuthorityTypeName, event.Scope, event.MintWide, event.CanTransfer, event.CanBurn = guardV3AuthorityTypeSemantics(authorityType)
		newAuthority, _, err := guardV3DecodeInstructionOptionalPubkey(data[2:])
		if err != nil {
			return event, true, fmt.Errorf("decode SetAuthority new authority: %w", err)
		}
		event.NewAuthority = newAuthority
		event.Persistent = newAuthority != "revoked"
		event.Explanation = guardV3AuthorityTypeExplanation(authorityType, newAuthority)
	case 13:
		if len(data) < 10 || len(accounts) < 4 {
			return event, true, fmt.Errorf("ApproveChecked instruction is truncated")
		}
		decimals := int(data[9])
		event.Kind, event.Source, event.Mint, event.Delegate, event.CurrentAuthority = "approve_checked", accounts[0], accounts[1], accounts[2], accounts[3]
		event.Account, event.Decimals = event.Source, &decimals
		event.AmountRaw = strconv.FormatUint(binary.LittleEndian.Uint64(data[1:9]), 10)
		event.Amount = formatGuardRawAmount(event.AmountRaw, event.Decimals)
		event.Scope, event.Persistent = "single_token_account_allowance", true
		event.EffectivelyUnlimited = event.AmountRaw == strconv.FormatUint(math.MaxUint64, 10)
		event.Explanation = "The delegate may transfer up to the approved token amount without another owner signature until the allowance is spent or revoked."
	case 26:
		return decodeTransactionGuardV3TransferFeeEvent(event, accounts, data)
	case 35:
		if instruction.ProgramID != guardV3Token2022ProgramID {
			return event, false, nil
		}
		if len(data) < 33 || len(accounts) < 1 {
			return event, true, fmt.Errorf("InitializePermanentDelegate instruction is truncated")
		}
		event.Kind, event.Mint, event.Delegate = "initialize_permanent_delegate", accounts[0], guardV3Base58Encode(data[1:33])
		event.Account, event.NewAuthority = event.Mint, event.Delegate
		event.Scope, event.Persistent, event.MintWide = "all_token_accounts_for_mint", true, true
		event.CanTransfer, event.CanBurn = true, true
		event.ActiveAfterSimulation = boolPointer(true)
		event.Explanation = "This permanent delegate may transfer or burn tokens from any token account belonging to the mint."
	case 36:
		return decodeTransactionGuardV3TransferHookEvent(event, accounts, data)
	default:
		return event, false, nil
	}
	return event, true, nil
}

func guardV3DecodeInstructionOptionalPubkey(data []byte) (string, int, error) {
	if len(data) < 1 {
		return "", 0, fmt.Errorf("optional pubkey tag is missing")
	}
	switch data[0] {
	case 0:
		return "revoked", 1, nil
	case 1:
		if len(data) < 33 {
			return "", 0, fmt.Errorf("optional pubkey value is truncated")
		}
		return guardV3Base58Encode(data[1:33]), 33, nil
	default:
		return "", 0, fmt.Errorf("invalid optional pubkey tag %d", data[0])
	}
}

func guardV3DecodeOptionalNonZeroPubkey(data []byte) string {
	if len(data) < 32 {
		return ""
	}
	allZero := true
	for _, value := range data[:32] {
		if value != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "revoked"
	}
	return guardV3Base58Encode(data[:32])
}

func boolPointer(value bool) *bool { return &value }
