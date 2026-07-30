package handlers

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"koschei/api/internal/services"
)

const guardV3LookupTableMetaSize = 56

func resolveTransactionGuardV3AddressLookups(ctx context.Context, rpcURL string, decoded transactionGuardDecodedTransaction) (transactionGuardDecodedTransaction, []transactionFirewallFinding) {
	if decoded.AddressLookupCount == 0 {
		return decoded, nil
	}
	tableAddresses := make([]string, 0, len(decoded.LookupTables))
	for _, lookup := range decoded.LookupTables {
		if strings.TrimSpace(lookup.TableAddress) != "" {
			tableAddresses = append(tableAddresses, lookup.TableAddress)
		}
	}
	if len(tableAddresses) != decoded.AddressLookupCount {
		return decoded, []transactionFirewallFinding{{
			Code: "transaction_address_lookup_metadata_incomplete", Severity: "high", Title: "Address lookup metadata is incomplete",
			Evidence: fmt.Sprintf("decoded_lookup_tables=%d expected=%d", len(tableAddresses), decoded.AddressLookupCount), Score: 30,
		}}
	}
	accounts, ordered, err := services.SolanaGetMultipleAccountsBase64(ctx, rpcURL, tableAddresses)
	if err != nil {
		return decoded, []transactionFirewallFinding{{
			Code: "transaction_address_lookup_rpc_failed", Severity: "high", Title: "Address lookup tables could not be resolved",
			Evidence: compactGuardV3Evidence(err.Error()), Score: 30,
		}}
	}
	return resolveTransactionGuardV3LookupAccounts(decoded, ordered, accounts.Value)
}

func resolveTransactionGuardV3LookupAccounts(decoded transactionGuardDecodedTransaction, ordered []string, infos []*services.SolanaAccountInfo) (transactionGuardDecodedTransaction, []transactionFirewallFinding) {
	candidate := decoded
	candidate.LookupTables = append([]transactionGuardDecodedLookupTable(nil), decoded.LookupTables...)
	candidate.Limitations = append([]string(nil), decoded.Limitations...)
	candidate.loadedWritableAddresses = []string{}
	candidate.loadedReadonlyAddresses = []string{}

	accountByAddress := map[string]*services.SolanaAccountInfo{}
	for index, address := range ordered {
		if index < len(infos) {
			accountByAddress[strings.TrimSpace(address)] = infos[index]
		}
	}
	for index := range candidate.LookupTables {
		lookup := candidate.LookupTables[index]
		lookup.WritableIndexes = append([]int(nil), lookup.WritableIndexes...)
		lookup.ReadonlyIndexes = append([]int(nil), lookup.ReadonlyIndexes...)
		lookup.WritableAddresses = []string{}
		lookup.ReadonlyAddresses = []string{}
		info := accountByAddress[strings.TrimSpace(lookup.TableAddress)]
		if info == nil {
			lookup.Status = "account_unavailable"
			candidate.LookupTables[index] = lookup
			return decoded, guardV3LookupResolutionFailure("transaction_address_lookup_account_unavailable", lookup.TableAddress, "Lookup table account was not returned by RPC.")
		}
		if !strings.EqualFold(strings.TrimSpace(info.Owner), guardV3AddressLookupTableProgramID) {
			lookup.Status = "owner_mismatch"
			candidate.LookupTables[index] = lookup
			return decoded, guardV3LookupResolutionFailure("transaction_address_lookup_owner_mismatch", lookup.TableAddress, "Lookup table account is not owned by the pinned Solana Address Lookup Table program.")
		}
		data, err := guardV3AccountDataBytes(info.Data)
		if err != nil {
			lookup.Status = "decode_failed"
			candidate.LookupTables[index] = lookup
			return decoded, guardV3LookupResolutionFailure("transaction_address_lookup_decode_failed", lookup.TableAddress, err.Error())
		}
		addresses, err := parseTransactionGuardV3LookupTableAddresses(data)
		if err != nil {
			lookup.Status = "invalid_layout"
			candidate.LookupTables[index] = lookup
			return decoded, guardV3LookupResolutionFailure("transaction_address_lookup_invalid_layout", lookup.TableAddress, err.Error())
		}
		for _, addressIndex := range lookup.WritableIndexes {
			if addressIndex < 0 || addressIndex >= len(addresses) {
				lookup.Status = "index_out_of_range"
				candidate.LookupTables[index] = lookup
				return decoded, guardV3LookupResolutionFailure("transaction_address_lookup_index_out_of_range", lookup.TableAddress, fmt.Sprintf("writable index %d exceeds %d stored addresses", addressIndex, len(addresses)))
			}
			lookup.WritableAddresses = append(lookup.WritableAddresses, addresses[addressIndex])
		}
		for _, addressIndex := range lookup.ReadonlyIndexes {
			if addressIndex < 0 || addressIndex >= len(addresses) {
				lookup.Status = "index_out_of_range"
				candidate.LookupTables[index] = lookup
				return decoded, guardV3LookupResolutionFailure("transaction_address_lookup_index_out_of_range", lookup.TableAddress, fmt.Sprintf("readonly index %d exceeds %d stored addresses", addressIndex, len(addresses)))
			}
			lookup.ReadonlyAddresses = append(lookup.ReadonlyAddresses, addresses[addressIndex])
		}
		lookup.Resolved = true
		lookup.Status = "verified_rpc_address_lookup"
		candidate.LookupTables[index] = lookup
		candidate.loadedWritableAddresses = append(candidate.loadedWritableAddresses, lookup.WritableAddresses...)
	}
	for _, lookup := range candidate.LookupTables {
		candidate.loadedReadonlyAddresses = append(candidate.loadedReadonlyAddresses, lookup.ReadonlyAddresses...)
	}
	if len(candidate.loadedWritableAddresses) != candidate.LoadedWritableCount || len(candidate.loadedReadonlyAddresses) != candidate.LoadedReadonlyCount {
		return decoded, guardV3LookupResolutionFailure(
			"transaction_address_lookup_count_mismatch", "",
			fmt.Sprintf("resolved writable=%d/%d readonly=%d/%d", len(candidate.loadedWritableAddresses), candidate.LoadedWritableCount, len(candidate.loadedReadonlyAddresses), candidate.LoadedReadonlyCount),
		)
	}
	candidate.UnresolvedLookupAccountCount = 0
	candidate.Complete = true
	candidate.Status = "complete_with_verified_address_lookups"
	candidate.Limitations = removeGuardV3Limitation(candidate.Limitations, guardV3UnresolvedLookupLimitation)
	if err := rebuildTransactionGuardV3DecodedInstructions(&candidate); err != nil {
		return decoded, guardV3LookupResolutionFailure("transaction_address_lookup_rebuild_failed", "", err.Error())
	}
	findings := []transactionFirewallFinding{{
		Code: "transaction_address_lookup_resolved", Severity: "info", Title: "Versioned address lookup tables resolved",
		Evidence: fmt.Sprintf("Resolved %d lookup table(s), %d writable and %d readonly loaded account(s) through Solana RPC.", candidate.AddressLookupCount, candidate.LoadedWritableCount, candidate.LoadedReadonlyCount), Score: 0,
	}}
	findings = append(findings, transactionGuardV3InstructionFindings(candidate)...)
	return candidate, uniqueGuardV3Findings(findings)
}

func parseTransactionGuardV3LookupTableAddresses(data []byte) ([]string, error) {
	if len(data) < guardV3LookupTableMetaSize {
		return nil, fmt.Errorf("lookup table account data is shorter than %d bytes", guardV3LookupTableMetaSize)
	}
	if binary.LittleEndian.Uint32(data[:4]) != 1 {
		return nil, fmt.Errorf("lookup table account state discriminator is not initialized")
	}
	addressBytes := data[guardV3LookupTableMetaSize:]
	if len(addressBytes)%32 != 0 {
		return nil, fmt.Errorf("lookup table address region has %d trailing byte(s)", len(addressBytes)%32)
	}
	addresses := make([]string, 0, len(addressBytes)/32)
	for offset := 0; offset < len(addressBytes); offset += 32 {
		addresses = append(addresses, guardV3Base58Encode(addressBytes[offset:offset+32]))
	}
	return addresses, nil
}

func guardV3AccountDataBytes(raw any) ([]byte, error) {
	encoded := ""
	switch value := raw.(type) {
	case []any:
		if len(value) > 0 {
			encoded, _ = value[0].(string)
		}
	case []string:
		if len(value) > 0 {
			encoded = value[0]
		}
	case string:
		encoded = value
	}
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, fmt.Errorf("lookup table base64 account data is unavailable")
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode lookup table account data: %w", err)
	}
	return decoded, nil
}

func guardV3LookupResolutionFailure(code, table, evidence string) []transactionFirewallFinding {
	if strings.TrimSpace(table) != "" {
		evidence = "table=" + strings.TrimSpace(table) + " " + evidence
	}
	return []transactionFirewallFinding{{
		Code: code, Severity: "high", Title: "Address lookup table resolution is incomplete",
		Evidence: compactGuardV3Evidence(evidence), Score: 30,
	}}
}

func refreshTransactionGuardV3InstructionFindings(findings []transactionFirewallFinding, decoded transactionGuardDecodedTransaction, replacement []transactionFirewallFinding) []transactionFirewallFinding {
	for _, code := range []string{
		"decoded_sol_transfer", "decoded_delegate_approval", "decoded_authority_change",
		"decoded_close_account", "decoded_freeze_account", "decoded_token_burn",
	} {
		findings = removeGuardV3Finding(findings, code)
	}
	if decoded.Complete {
		findings = removeGuardV3Finding(findings, "transaction_address_lookup_unresolved")
	}
	return uniqueGuardV3Findings(append(findings, replacement...))
}
