package handlers

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

func decodeTransactionGuardV3TransferFeeEvent(event transactionGuardAuthorityEvent, accounts []string, data []byte) (transactionGuardAuthorityEvent, bool, error) {
	if event.ProgramID != guardV3Token2022ProgramID {
		return event, false, nil
	}
	if len(data) < 2 {
		return event, true, fmt.Errorf("TransferFee extension instruction is truncated")
	}
	switch data[1] {
	case 0:
		if len(accounts) < 1 {
			return event, true, fmt.Errorf("InitializeTransferFeeConfig mint is missing")
		}
		offset := 2
		configAuthority, used, err := guardV3DecodeInstructionOptionalPubkey(data[offset:])
		if err != nil {
			return event, true, err
		}
		offset += used
		withdrawAuthority, used, err := guardV3DecodeInstructionOptionalPubkey(data[offset:])
		if err != nil {
			return event, true, err
		}
		offset += used
		if len(data) < offset+10 {
			return event, true, fmt.Errorf("InitializeTransferFeeConfig values are truncated")
		}
		bps := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		event.Kind, event.Mint, event.Account = "initialize_transfer_fee_config", accounts[0], accounts[0]
		event.NewAuthority, event.WithdrawWithheldAuthority = configAuthority, withdrawAuthority
		event.TransferFeeBasisPoints, event.MaximumFeeRaw = &bps, strconv.FormatUint(binary.LittleEndian.Uint64(data[offset+2:offset+10]), 10)
		event.Scope, event.Persistent, event.MintWide = "all_future_transfers_for_mint", configAuthority != "revoked" || withdrawAuthority != "revoked", true
		event.Explanation = fmt.Sprintf("The mint charges %d basis points on transfers, capped at %s raw units; configured authorities may update fees or withdraw withheld fees.", bps, event.MaximumFeeRaw)
	case 1:
		if len(data) < 19 || len(accounts) < 4 {
			return event, true, fmt.Errorf("TransferCheckedWithFee instruction is truncated")
		}
		decimals := int(data[10])
		event.Kind, event.Source, event.Mint, event.Destination, event.CurrentAuthority = "transfer_checked_with_fee", accounts[0], accounts[1], accounts[2], accounts[3]
		event.AmountRaw, event.Decimals = strconv.FormatUint(binary.LittleEndian.Uint64(data[2:10]), 10), &decimals
		event.Amount = formatGuardRawAmount(event.AmountRaw, event.Decimals)
		event.ExpectedFeeRaw = strconv.FormatUint(binary.LittleEndian.Uint64(data[11:19]), 10)
		event.Scope = "single_transfer_fee"
		event.Explanation = "This transfer declares the exact Token-2022 fee expected to be withheld in the destination account."
	case 2:
		if len(accounts) < 3 {
			return event, true, fmt.Errorf("WithdrawWithheldTokensFromMint accounts are truncated")
		}
		event.Kind, event.Mint, event.Destination, event.CurrentAuthority = "withdraw_withheld_tokens_from_mint", accounts[0], accounts[1], accounts[2]
		event.Scope = "withheld_fees_on_mint"
		event.Explanation = "Withheld transfer fees stored on the mint are withdrawn to the destination token account."
	case 3:
		if len(data) < 3 || len(accounts) < 3 {
			return event, true, fmt.Errorf("WithdrawWithheldTokensFromAccounts instruction is truncated")
		}
		event.Kind, event.Mint, event.Destination, event.CurrentAuthority = "withdraw_withheld_tokens_from_accounts", accounts[0], accounts[1], accounts[2]
		event.AmountRaw = strconv.Itoa(int(data[2]))
		event.Scope = "withheld_fees_on_token_accounts"
		event.Explanation = "Withheld transfer fees are collected from token accounts into the destination token account."
	case 4:
		if len(accounts) < 1 {
			return event, true, fmt.Errorf("HarvestWithheldTokensToMint mint is missing")
		}
		event.Kind, event.Mint, event.Account = "harvest_withheld_tokens_to_mint", accounts[0], accounts[0]
		event.Scope = "withheld_fees_on_token_accounts"
		event.Explanation = "Withheld fees are harvested from token accounts into the mint."
	case 5:
		if len(data) < 12 || len(accounts) < 2 {
			return event, true, fmt.Errorf("SetTransferFee instruction is truncated")
		}
		bps := int(binary.LittleEndian.Uint16(data[2:4]))
		event.Kind, event.Mint, event.Account, event.CurrentAuthority = "set_transfer_fee", accounts[0], accounts[0], accounts[1]
		event.TransferFeeBasisPoints, event.MaximumFeeRaw = &bps, strconv.FormatUint(binary.LittleEndian.Uint64(data[4:12]), 10)
		event.Scope, event.Persistent, event.MintWide = "all_future_transfers_for_mint", true, true
		event.Explanation = fmt.Sprintf("The transfer fee is set to %d basis points with a maximum fee of %s raw units.", bps, event.MaximumFeeRaw)
	default:
		return event, true, fmt.Errorf("unknown TransferFee extension sub-instruction %d", data[1])
	}
	return event, true, nil
}

func decodeTransactionGuardV3TransferHookEvent(event transactionGuardAuthorityEvent, accounts []string, data []byte) (transactionGuardAuthorityEvent, bool, error) {
	if event.ProgramID != guardV3Token2022ProgramID {
		return event, false, nil
	}
	if len(data) < 2 || len(accounts) < 1 {
		return event, true, fmt.Errorf("TransferHook extension instruction is truncated")
	}
	event.Mint, event.Account, event.Scope, event.MintWide = accounts[0], accounts[0], "all_future_transfers_for_mint", true
	switch data[1] {
	case 0:
		if len(data) < 66 {
			return event, true, fmt.Errorf("TransferHook Initialize data is truncated")
		}
		event.Kind = "initialize_transfer_hook"
		event.NewAuthority = guardV3DecodeOptionalNonZeroPubkey(data[2:34])
		event.TransferHookProgramID = guardV3DecodeOptionalNonZeroPubkey(data[34:66])
		event.Persistent = event.TransferHookProgramID != "revoked"
		event.ActiveAfterSimulation = boolPointer(event.Persistent)
		event.Explanation = "Every future transfer for this mint may invoke the configured transfer-hook program."
	case 1:
		if len(data) < 34 || len(accounts) < 2 {
			return event, true, fmt.Errorf("TransferHook Update data is truncated")
		}
		event.Kind, event.CurrentAuthority = "update_transfer_hook", accounts[1]
		event.TransferHookProgramID = guardV3DecodeOptionalNonZeroPubkey(data[2:34])
		event.Persistent = event.TransferHookProgramID != "revoked"
		event.ActiveAfterSimulation = boolPointer(event.Persistent)
		if event.Persistent {
			event.Explanation = "The program invoked by every future transfer for this mint is changed."
		} else {
			event.Explanation = "The transfer-hook program is removed from the mint."
		}
	default:
		return event, true, fmt.Errorf("unknown TransferHook extension sub-instruction %d", data[1])
	}
	return event, true, nil
}
