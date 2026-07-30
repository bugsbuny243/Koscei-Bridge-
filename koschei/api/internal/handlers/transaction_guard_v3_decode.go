package handlers

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

const guardV3UnresolvedLookupLimitation = "Versioned address-table accounts were counted but not resolved; recipient and program coverage is incomplete until lookup tables are fetched."

func decodeTransactionGuardV3(transaction, encoding, wallet string) (transactionGuardDecodedTransaction, []transactionFirewallFinding) {
	out := transactionGuardDecodedTransaction{
		Status:          "decode_failed",
		StaticAccounts:  []transactionGuardDecodedAccount{},
		LoadedAccounts:  []transactionGuardDecodedAccount{},
		LookupTables:    []transactionGuardDecodedLookupTable{},
		ProgramIDs:      []string{},
		Instructions:    []transactionGuardDecodedInstruction{},
		SOLTransfers:    []transactionGuardDecodedSOLTransfer{},
		TokenOperations: []transactionGuardDecodedTokenOperation{},
		Limitations:     []string{},
	}
	findings := []transactionFirewallFinding{}
	if strings.ToLower(strings.TrimSpace(encoding)) != "base64" {
		return out, []transactionFirewallFinding{{Code: "transaction_decode_unsupported_encoding", Severity: "high", Title: "Serialized transaction could not be decoded", Evidence: "Transaction Guard v3 requires base64 transaction bytes.", Score: 30}}
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(transaction))
	if err != nil {
		return out, []transactionFirewallFinding{{Code: "transaction_decode_failed", Severity: "high", Title: "Serialized transaction could not be decoded", Evidence: "Invalid base64 transaction payload.", Score: 30}}
	}
	if err := parseTransactionGuardV3(raw, strings.TrimSpace(wallet), &out); err != nil {
		out.Limitations = append(out.Limitations, err.Error())
		return out, []transactionFirewallFinding{{Code: "transaction_decode_failed", Severity: "high", Title: "Serialized transaction structure is invalid", Evidence: compactGuardV3Evidence(err.Error()), Score: 30}}
	}
	out.Available = true
	out.Complete = out.UnresolvedLookupAccountCount == 0
	out.Status = "complete"
	if !out.Complete {
		out.Status = "complete_with_unresolved_address_lookups"
		out.Limitations = append(out.Limitations, guardV3UnresolvedLookupLimitation)
		findings = append(findings, transactionFirewallFinding{
			Code: "transaction_address_lookup_unresolved", Severity: "high", Title: "Versioned address-table accounts are unresolved",
			Evidence: fmt.Sprintf("%d loaded account(s) across %d lookup table(s) require RPC resolution.", out.UnresolvedLookupAccountCount, out.AddressLookupCount), Score: 30,
		})
	}
	out.Limitations = append(out.Limitations,
		"Decoded amounts cover explicit outer instructions only; CPI transfers, rent changes and the network fee require simulation balance deltas.",
		"A decoded transfer is factual transaction intent and is not, by itself, a maliciousness finding.",
	)
	findings = append(findings, transactionGuardV3InstructionFindings(out)...)
	return out, uniqueGuardV3Findings(findings)
}

func parseTransactionGuardV3(raw []byte, wallet string, out *transactionGuardDecodedTransaction) error {
	if out == nil {
		return fmt.Errorf("decoded transaction output is nil")
	}
	offset := 0
	signatureCount, err := readGuardV3ShortVec(raw, &offset)
	if err != nil {
		return fmt.Errorf("signature count: %w", err)
	}
	out.SignatureCount = signatureCount
	if signatureCount < 0 || signatureCount > 64 {
		return fmt.Errorf("signature count %d is outside the supported range", signatureCount)
	}
	signatureBytes := signatureCount * 64
	if offset+signatureBytes > len(raw) {
		return fmt.Errorf("serialized transaction signatures are truncated")
	}
	offset += signatureBytes
	if offset >= len(raw) {
		return fmt.Errorf("serialized transaction message is missing")
	}

	versioned := raw[offset]&0x80 != 0
	if versioned {
		version := int(raw[offset] & 0x7f)
		out.Version = "v" + strconv.Itoa(version)
		if version != 0 {
			return fmt.Errorf("unsupported Solana message version %d", version)
		}
		offset++
	} else {
		out.Version = "legacy"
	}
	if offset+3 > len(raw) {
		return fmt.Errorf("message header is truncated")
	}
	requiredSignatures := int(raw[offset])
	readonlySigned := int(raw[offset+1])
	readonlyUnsigned := int(raw[offset+2])
	offset += 3
	out.RequiredSignatureCount = requiredSignatures
	if signatureCount != requiredSignatures {
		return fmt.Errorf("signature count %d does not match required signature count %d", signatureCount, requiredSignatures)
	}

	accountCount, err := readGuardV3ShortVec(raw, &offset)
	if err != nil {
		return fmt.Errorf("static account count: %w", err)
	}
	if accountCount <= 0 || accountCount > 256 {
		return fmt.Errorf("static account count %d is outside the supported range", accountCount)
	}
	if requiredSignatures > accountCount || readonlySigned > requiredSignatures || readonlyUnsigned > accountCount-requiredSignatures {
		return fmt.Errorf("message header account permissions are inconsistent")
	}
	if offset+accountCount*32 > len(raw) {
		return fmt.Errorf("static account keys are truncated")
	}
	staticAddresses := make([]string, accountCount)
	writableSigned := requiredSignatures - readonlySigned
	writableUnsignedEnd := accountCount - readonlyUnsigned
	for index := 0; index < accountCount; index++ {
		address := guardV3Base58Encode(raw[offset : offset+32])
		offset += 32
		staticAddresses[index] = address
		signer := index < requiredSignatures
		writable := false
		if signer {
			writable = index < writableSigned
		} else {
			writable = index < writableUnsignedEnd
		}
		out.StaticAccounts = append(out.StaticAccounts, transactionGuardDecodedAccount{Index: index, Address: address, Signer: signer, Writable: writable, Source: "static_message"})
	}
	out.StaticAccountCount = len(staticAddresses)
	if len(staticAddresses) > 0 {
		out.FeePayer = staticAddresses[0]
	}
	if offset+32 > len(raw) {
		return fmt.Errorf("recent blockhash is truncated")
	}
	offset += 32

	instructionCount, err := readGuardV3ShortVec(raw, &offset)
	if err != nil {
		return fmt.Errorf("instruction count: %w", err)
	}
	if instructionCount < 0 || instructionCount > 256 {
		return fmt.Errorf("instruction count %d is outside the supported range", instructionCount)
	}
	parsedInstructions := make([]guardV3ParsedInstruction, 0, instructionCount)
	for index := 0; index < instructionCount; index++ {
		if offset >= len(raw) {
			return fmt.Errorf("instruction %d program index is truncated", index)
		}
		programIndex := int(raw[offset])
		offset++
		accountIndexCount, err := readGuardV3ShortVec(raw, &offset)
		if err != nil {
			return fmt.Errorf("instruction %d account indexes: %w", index, err)
		}
		if accountIndexCount < 0 || accountIndexCount > 256 || offset+accountIndexCount > len(raw) {
			return fmt.Errorf("instruction %d account indexes are truncated", index)
		}
		accountIndexes := make([]int, accountIndexCount)
		for i := 0; i < accountIndexCount; i++ {
			accountIndexes[i] = int(raw[offset+i])
		}
		offset += accountIndexCount
		dataLength, err := readGuardV3ShortVec(raw, &offset)
		if err != nil {
			return fmt.Errorf("instruction %d data length: %w", index, err)
		}
		if dataLength < 0 || dataLength > len(raw)-offset {
			return fmt.Errorf("instruction %d data is truncated", index)
		}
		data := append([]byte(nil), raw[offset:offset+dataLength]...)
		offset += dataLength
		parsedInstructions = append(parsedInstructions, guardV3ParsedInstruction{ProgramIndex: programIndex, AccountIndexes: accountIndexes, Data: data})
	}

	if versioned {
		lookupCount, err := readGuardV3ShortVec(raw, &offset)
		if err != nil {
			return fmt.Errorf("address lookup count: %w", err)
		}
		out.AddressLookupCount = lookupCount
		for index := 0; index < lookupCount; index++ {
			if offset+32 > len(raw) {
				return fmt.Errorf("address lookup %d account key is truncated", index)
			}
			tableAddress := guardV3Base58Encode(raw[offset : offset+32])
			offset += 32
			writableCount, err := readGuardV3ShortVec(raw, &offset)
			if err != nil {
				return fmt.Errorf("address lookup %d writable indexes: %w", index, err)
			}
			if writableCount < 0 || offset+writableCount > len(raw) {
				return fmt.Errorf("address lookup %d writable indexes are truncated", index)
			}
			writableIndexes := make([]int, writableCount)
			for item := 0; item < writableCount; item++ {
				writableIndexes[item] = int(raw[offset+item])
			}
			offset += writableCount
			readonlyCount, err := readGuardV3ShortVec(raw, &offset)
			if err != nil {
				return fmt.Errorf("address lookup %d readonly indexes: %w", index, err)
			}
			if readonlyCount < 0 || offset+readonlyCount > len(raw) {
				return fmt.Errorf("address lookup %d readonly indexes are truncated", index)
			}
			readonlyIndexes := make([]int, readonlyCount)
			for item := 0; item < readonlyCount; item++ {
				readonlyIndexes[item] = int(raw[offset+item])
			}
			offset += readonlyCount
			out.LoadedWritableCount += writableCount
			out.LoadedReadonlyCount += readonlyCount
			out.LookupTables = append(out.LookupTables, transactionGuardDecodedLookupTable{
				TableAddress: tableAddress, WritableIndexes: writableIndexes, ReadonlyIndexes: readonlyIndexes,
				WritableAddresses: []string{}, ReadonlyAddresses: []string{}, Status: "rpc_resolution_required",
			})
		}
	}
	if offset != len(raw) {
		return fmt.Errorf("serialized transaction contains %d trailing byte(s)", len(raw)-offset)
	}
	out.UnresolvedLookupAccountCount = out.LoadedWritableCount + out.LoadedReadonlyCount
	if len(staticAddresses)+out.UnresolvedLookupAccountCount > 256 {
		return fmt.Errorf("message account count exceeds the compiled-index range")
	}
	out.staticAddresses = append([]string(nil), staticAddresses...)
	out.parsedInstructions = append([]guardV3ParsedInstruction(nil), parsedInstructions...)
	out.declaredWallet = wallet
	return rebuildTransactionGuardV3DecodedInstructions(out)
}

func rebuildTransactionGuardV3DecodedInstructions(out *transactionGuardDecodedTransaction) error {
	if out == nil {
		return fmt.Errorf("decoded transaction output is nil")
	}
	staticAddresses := out.staticAddresses
	if len(staticAddresses) == 0 && len(out.StaticAccounts) > 0 {
		staticAddresses = make([]string, len(out.StaticAccounts))
		for index, account := range out.StaticAccounts {
			staticAddresses[index] = account.Address
		}
	}
	out.Instructions = []transactionGuardDecodedInstruction{}
	out.ProgramIDs = []string{}
	out.SOLTransfers = []transactionGuardDecodedSOLTransfer{}
	out.TokenOperations = []transactionGuardDecodedTokenOperation{}
	out.LoadedAccounts = []transactionGuardDecodedAccount{}
	out.ExplicitSOLTransferLamports = "0"
	out.DeclaredWalletSOLSpend = ""

	for index := 0; index < out.LoadedWritableCount; index++ {
		address := guardV3LookupPlaceholder(len(staticAddresses)+index, len(staticAddresses), out.LoadedWritableCount)
		if index < len(out.loadedWritableAddresses) && strings.TrimSpace(out.loadedWritableAddresses[index]) != "" {
			address = out.loadedWritableAddresses[index]
		}
		out.LoadedAccounts = append(out.LoadedAccounts, transactionGuardDecodedAccount{
			Index: len(staticAddresses) + index, Address: address, Writable: true, Source: "address_lookup_table",
		})
	}
	for index := 0; index < out.LoadedReadonlyCount; index++ {
		accountIndex := len(staticAddresses) + out.LoadedWritableCount + index
		address := guardV3LookupPlaceholder(accountIndex, len(staticAddresses), out.LoadedWritableCount)
		if index < len(out.loadedReadonlyAddresses) && strings.TrimSpace(out.loadedReadonlyAddresses[index]) != "" {
			address = out.loadedReadonlyAddresses[index]
		}
		out.LoadedAccounts = append(out.LoadedAccounts, transactionGuardDecodedAccount{
			Index: accountIndex, Address: address, Writable: false, Source: "address_lookup_table",
		})
	}

	programSet := map[string]bool{}
	totalAccountCount := len(staticAddresses) + out.LoadedWritableCount + out.LoadedReadonlyCount
	for index, parsed := range out.parsedInstructions {
		instruction := transactionGuardDecodedInstruction{
			Index: index, AccountIndexes: append([]int(nil), parsed.AccountIndexes...), Accounts: []string{}, DataLength: len(parsed.Data),
		}
		if parsed.ProgramIndex < 0 || parsed.ProgramIndex >= totalAccountCount {
			return fmt.Errorf("instruction %d references program index %d outside %d accounts", index, parsed.ProgramIndex, totalAccountCount)
		}
		instruction.ProgramID, instruction.ProgramResolved = transactionGuardV3AccountAddress(out, parsed.ProgramIndex)
		if instruction.ProgramResolved {
			programSet[instruction.ProgramID] = true
		}
		for _, accountIndex := range parsed.AccountIndexes {
			if accountIndex < 0 || accountIndex >= totalAccountCount {
				return fmt.Errorf("instruction %d references account index %d outside %d accounts", index, accountIndex, totalAccountCount)
			}
			address, _ := transactionGuardV3AccountAddress(out, accountIndex)
			instruction.Accounts = append(instruction.Accounts, address)
		}
		prefixLength := len(parsed.Data)
		if prefixLength > 16 {
			prefixLength = 16
		}
		if prefixLength > 0 {
			instruction.DataPrefixHex = hex.EncodeToString(parsed.Data[:prefixLength])
		}
		if instruction.ProgramResolved {
			instruction.Kind = classifyTransactionGuardV3Instruction(instruction.ProgramID, instruction.Accounts, parsed.Data, out)
		} else {
			instruction.Kind = "unresolved_program"
		}
		out.Instructions = append(out.Instructions, instruction)
	}
	for program := range programSet {
		out.ProgramIDs = append(out.ProgramIDs, program)
	}
	sort.Strings(out.ProgramIDs)

	totalSOL := big.NewInt(0)
	walletSOL := big.NewInt(0)
	for _, transfer := range out.SOLTransfers {
		amount := new(big.Int)
		if _, ok := amount.SetString(transfer.Lamports, 10); !ok {
			continue
		}
		totalSOL.Add(totalSOL, amount)
		if out.declaredWallet != "" && strings.EqualFold(out.declaredWallet, transfer.Source) {
			walletSOL.Add(walletSOL, amount)
		}
	}
	out.ExplicitSOLTransferLamports = totalSOL.String()
	if out.declaredWallet != "" {
		out.DeclaredWalletSOLSpend = walletSOL.String()
	}
	return nil
}

func transactionGuardV3AccountAddress(out *transactionGuardDecodedTransaction, index int) (string, bool) {
	if out == nil {
		return "unresolved-account:" + strconv.Itoa(index), false
	}
	if index >= 0 && index < len(out.staticAddresses) {
		return out.staticAddresses[index], true
	}
	loadedIndex := index - len(out.staticAddresses)
	if loadedIndex >= 0 && loadedIndex < out.LoadedWritableCount {
		if loadedIndex < len(out.loadedWritableAddresses) && strings.TrimSpace(out.loadedWritableAddresses[loadedIndex]) != "" {
			return out.loadedWritableAddresses[loadedIndex], true
		}
		return guardV3LookupPlaceholder(index, len(out.staticAddresses), out.LoadedWritableCount), false
	}
	readonlyIndex := loadedIndex - out.LoadedWritableCount
	if readonlyIndex >= 0 && readonlyIndex < out.LoadedReadonlyCount {
		if readonlyIndex < len(out.loadedReadonlyAddresses) && strings.TrimSpace(out.loadedReadonlyAddresses[readonlyIndex]) != "" {
			return out.loadedReadonlyAddresses[readonlyIndex], true
		}
		return guardV3LookupPlaceholder(index, len(out.staticAddresses), out.LoadedWritableCount), false
	}
	return "unresolved-account:" + strconv.Itoa(index), false
}
