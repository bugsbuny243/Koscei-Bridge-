package handlers

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

func classifyTransactionGuardV3Instruction(programID string, accounts []string, data []byte, out *transactionGuardDecodedTransaction) string {
	switch programID {
	case guardV3SystemProgramID:
		return classifyTransactionGuardV3SystemInstruction(accounts, data, out)
	case guardV3SPLTokenProgramID, guardV3Token2022ProgramID:
		return classifyTransactionGuardV3TokenInstruction(programID, accounts, data, out)
	default:
		return "unclassified"
	}
}

func classifyTransactionGuardV3SystemInstruction(accounts []string, data []byte, out *transactionGuardDecodedTransaction) string {
	if len(data) < 4 {
		return "system_unparsed"
	}
	opcode := binary.LittleEndian.Uint32(data[:4])
	switch opcode {
	case 0:
		if len(data) < 52 || len(accounts) < 2 {
			return "system_create_account_unparsed"
		}
		out.SOLTransfers = append(out.SOLTransfers, transactionGuardDecodedSOLTransfer{
			Kind: "create_account", Source: accounts[0], Recipient: accounts[1], Lamports: strconv.FormatUint(binary.LittleEndian.Uint64(data[4:12]), 10),
			SpaceBytes: strconv.FormatUint(binary.LittleEndian.Uint64(data[12:20]), 10), Owner: guardV3Base58Encode(data[20:52]),
		})
		return "system_create_account"
	case 2:
		if len(data) < 12 || len(accounts) < 2 {
			return "system_transfer_unparsed"
		}
		out.SOLTransfers = append(out.SOLTransfers, transactionGuardDecodedSOLTransfer{
			Kind: "transfer", Source: accounts[0], Recipient: accounts[1], Lamports: strconv.FormatUint(binary.LittleEndian.Uint64(data[4:12]), 10),
		})
		return "system_transfer"
	default:
		return "system_instruction_" + strconv.FormatUint(uint64(opcode), 10)
	}
}

func classifyTransactionGuardV3TokenInstruction(programID string, accounts []string, data []byte, out *transactionGuardDecodedTransaction) string {
	if len(data) == 0 {
		return "token_unparsed"
	}
	opcode := int(data[0])
	if guardV3AuthorityOpcode(opcode) {
		event, relevant, err := decodeTransactionGuardV3AuthorityEvent(transactionGuardAuthorityInstruction{
			Source: "decoded", ProgramID: programID, Accounts: accounts, Data: data,
		})
		if err != nil {
			return "token_authority_instruction_unparsed"
		}
		if relevant {
			if operation, ok := guardV3DecodedTokenOperationFromAuthorityEvent(event); ok {
				out.TokenOperations = append(out.TokenOperations, operation)
			} else if event.Kind == "transfer_checked_with_fee" {
				out.TokenOperations = append(out.TokenOperations, transactionGuardDecodedTokenOperation{
					Kind: "transfer_checked", ProgramID: programID, Source: event.Source, Destination: event.Destination,
					Mint: event.Mint, Authority: event.CurrentAuthority, AmountRaw: event.AmountRaw, Decimals: event.Decimals,
				})
			}
			return "token_" + event.Kind
		}
	}

	operation := transactionGuardDecodedTokenOperation{ProgramID: programID}
	switch opcode {
	case 3:
		if len(data) < 9 || len(accounts) < 3 {
			return "token_transfer_unparsed"
		}
		operation.Kind, operation.Source, operation.Destination, operation.Authority = "transfer", accounts[0], accounts[1], accounts[2]
		operation.AmountRaw = strconv.FormatUint(binary.LittleEndian.Uint64(data[1:9]), 10)
	case 8:
		if len(data) < 9 || len(accounts) < 3 {
			return "token_burn_unparsed"
		}
		operation.Kind, operation.Account, operation.Mint, operation.Authority = "burn", accounts[0], accounts[1], accounts[2]
		operation.AmountRaw = strconv.FormatUint(binary.LittleEndian.Uint64(data[1:9]), 10)
	case 9:
		if len(accounts) < 3 {
			return "token_close_account_unparsed"
		}
		operation.Kind, operation.Account, operation.Destination, operation.Authority = "close_account", accounts[0], accounts[1], accounts[2]
	case 10:
		if len(accounts) < 3 {
			return "token_freeze_account_unparsed"
		}
		operation.Kind, operation.Account, operation.Mint, operation.Authority = "freeze_account", accounts[0], accounts[1], accounts[2]
	case 11:
		if len(accounts) < 3 {
			return "token_thaw_account_unparsed"
		}
		operation.Kind, operation.Account, operation.Mint, operation.Authority = "thaw_account", accounts[0], accounts[1], accounts[2]
	case 12:
		if len(data) < 10 || len(accounts) < 4 {
			return "token_transfer_checked_unparsed"
		}
		decimals := int(data[9])
		operation.Kind, operation.Source, operation.Mint, operation.Destination, operation.Authority = "transfer_checked", accounts[0], accounts[1], accounts[2], accounts[3]
		operation.AmountRaw, operation.Decimals = strconv.FormatUint(binary.LittleEndian.Uint64(data[1:9]), 10), &decimals
	case 15:
		if len(data) < 10 || len(accounts) < 3 {
			return "token_burn_checked_unparsed"
		}
		decimals := int(data[9])
		operation.Kind, operation.Account, operation.Mint, operation.Authority = "burn_checked", accounts[0], accounts[1], accounts[2]
		operation.AmountRaw, operation.Decimals = strconv.FormatUint(binary.LittleEndian.Uint64(data[1:9]), 10), &decimals
	default:
		return "token_instruction_" + strconv.Itoa(opcode)
	}
	out.TokenOperations = append(out.TokenOperations, operation)
	return "token_" + operation.Kind
}

func guardV3AuthorityOpcode(opcode int) bool {
	switch opcode {
	case 4, 5, 6, 13, 26, 35, 36:
		return true
	default:
		return false
	}
}

func transactionGuardV3InstructionFindings(decoded transactionGuardDecodedTransaction) []transactionFirewallFinding {
	findings := []transactionFirewallFinding{}
	for _, transfer := range decoded.SOLTransfers {
		findings = append(findings, transactionFirewallFinding{
			Code: "decoded_sol_transfer", Severity: "info", Title: "Explicit SOL movement decoded",
			Evidence: fmt.Sprintf("%s sends %s lamports to %s via %s.", transfer.Source, transfer.Lamports, transfer.Recipient, transfer.Kind), Score: 0,
		})
	}
	for _, operation := range decoded.TokenOperations {
		switch operation.Kind {
		case "approve", "approve_checked":
			findings = append(findings, transactionFirewallFinding{Code: "decoded_delegate_approval", Severity: "medium", Title: "Token delegate approval decoded", Evidence: fmt.Sprintf("source=%s delegate=%s amount_raw=%s", operation.Source, operation.Delegate, operation.AmountRaw), Score: 18})
		case "set_authority":
			findings = append(findings, transactionFirewallFinding{Code: "decoded_authority_change", Severity: "high", Title: "Token authority change decoded", Evidence: fmt.Sprintf("account=%s authority_type=%d new_authority=%s", operation.Account, guardV3IntValue(operation.AuthorityType), operation.NewAuthority), Score: 35})
		case "close_account":
			findings = append(findings, transactionFirewallFinding{Code: "decoded_close_account", Severity: "medium", Title: "Token account closure decoded", Evidence: fmt.Sprintf("account=%s rent_destination=%s", operation.Account, operation.Destination), Score: 20})
		case "freeze_account":
			findings = append(findings, transactionFirewallFinding{Code: "decoded_freeze_account", Severity: "high", Title: "Token account freeze decoded", Evidence: fmt.Sprintf("account=%s mint=%s authority=%s", operation.Account, operation.Mint, operation.Authority), Score: 30})
		case "burn", "burn_checked":
			findings = append(findings, transactionFirewallFinding{Code: "decoded_token_burn", Severity: "medium", Title: "Token burn decoded", Evidence: fmt.Sprintf("account=%s mint=%s amount_raw=%s", operation.Account, operation.Mint, operation.AmountRaw), Score: 15})
		}
	}
	return uniqueGuardV3Findings(findings)
}
