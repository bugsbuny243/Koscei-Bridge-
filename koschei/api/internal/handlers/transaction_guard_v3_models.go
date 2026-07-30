package handlers

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

const (
	guardV3SystemProgramID             = "11111111111111111111111111111111"
	guardV3SPLTokenProgramID           = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	guardV3Token2022ProgramID          = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
	guardV3AddressLookupTableProgramID = "AddressLookupTab1e1111111111111111111111111"
)

var guardV3Base58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

type transactionGuardDecodedAccount struct {
	Index    int    `json:"index"`
	Address  string `json:"address"`
	Signer   bool   `json:"signer"`
	Writable bool   `json:"writable"`
	Source   string `json:"source"`
}

type transactionGuardDecodedLookupTable struct {
	TableAddress      string   `json:"table_address"`
	WritableIndexes   []int    `json:"writable_indexes"`
	ReadonlyIndexes   []int    `json:"readonly_indexes"`
	Resolved          bool     `json:"resolved"`
	WritableAddresses []string `json:"writable_addresses"`
	ReadonlyAddresses []string `json:"readonly_addresses"`
	Status            string   `json:"status"`
}

type transactionGuardDecodedInstruction struct {
	Index           int      `json:"index"`
	ProgramID       string   `json:"program_id"`
	ProgramResolved bool     `json:"program_resolved"`
	AccountIndexes  []int    `json:"account_indexes"`
	Accounts        []string `json:"accounts"`
	DataLength      int      `json:"data_length"`
	DataPrefixHex   string   `json:"data_prefix_hex,omitempty"`
	Kind            string   `json:"kind,omitempty"`
}

type transactionGuardDecodedSOLTransfer struct {
	Kind       string `json:"kind"`
	Source     string `json:"source"`
	Recipient  string `json:"recipient"`
	Lamports   string `json:"lamports"`
	Owner      string `json:"owner,omitempty"`
	SpaceBytes string `json:"space_bytes,omitempty"`
}

type transactionGuardDecodedTokenOperation struct {
	Kind          string `json:"kind"`
	ProgramID     string `json:"program_id"`
	Account       string `json:"account,omitempty"`
	Source        string `json:"source,omitempty"`
	Destination   string `json:"destination,omitempty"`
	Mint          string `json:"mint,omitempty"`
	Authority     string `json:"authority,omitempty"`
	Delegate      string `json:"delegate,omitempty"`
	AmountRaw     string `json:"amount_raw,omitempty"`
	Decimals      *int   `json:"decimals,omitempty"`
	AuthorityType *int   `json:"authority_type,omitempty"`
	NewAuthority  string `json:"new_authority,omitempty"`
}

type transactionGuardDecodedTransaction struct {
	Available                    bool                                    `json:"available"`
	Complete                     bool                                    `json:"complete"`
	Status                       string                                  `json:"status"`
	Version                      string                                  `json:"version"`
	SignatureCount               int                                     `json:"signature_count"`
	RequiredSignatureCount       int                                     `json:"required_signature_count"`
	FeePayer                     string                                  `json:"fee_payer,omitempty"`
	StaticAccountCount           int                                     `json:"static_account_count"`
	AddressLookupCount           int                                     `json:"address_lookup_count"`
	LoadedWritableCount          int                                     `json:"loaded_writable_count"`
	LoadedReadonlyCount          int                                     `json:"loaded_readonly_count"`
	UnresolvedLookupAccountCount int                                     `json:"unresolved_lookup_account_count"`
	StaticAccounts               []transactionGuardDecodedAccount        `json:"static_accounts"`
	LoadedAccounts               []transactionGuardDecodedAccount        `json:"loaded_accounts"`
	LookupTables                 []transactionGuardDecodedLookupTable    `json:"lookup_tables"`
	ProgramIDs                   []string                                `json:"program_ids"`
	Instructions                 []transactionGuardDecodedInstruction    `json:"instructions"`
	SOLTransfers                 []transactionGuardDecodedSOLTransfer    `json:"sol_transfers"`
	TokenOperations              []transactionGuardDecodedTokenOperation `json:"token_operations"`
	ExplicitSOLTransferLamports  string                                  `json:"explicit_sol_transfer_lamports"`
	DeclaredWalletSOLSpend       string                                  `json:"declared_wallet_sol_spend_lamports,omitempty"`
	Limitations                  []string                                `json:"limitations"`
	staticAddresses              []string
	parsedInstructions           []guardV3ParsedInstruction
	loadedWritableAddresses      []string
	loadedReadonlyAddresses      []string
	declaredWallet               string
}

type guardV3ParsedInstruction struct {
	ProgramIndex   int
	AccountIndexes []int
	Data           []byte
}

func readGuardV3ShortVec(data []byte, offset *int) (int, error) {
	if offset == nil {
		return 0, fmt.Errorf("offset is nil")
	}
	value := 0
	shift := uint(0)
	for count := 0; count < 4; count++ {
		if *offset >= len(data) {
			return 0, fmt.Errorf("shortvec is truncated")
		}
		current := data[*offset]
		(*offset)++
		value |= int(current&0x7f) << shift
		if current&0x80 == 0 {
			return value, nil
		}
		shift += 7
	}
	return 0, fmt.Errorf("shortvec exceeds the supported length")
}

func guardV3AddressForIndex(index int, static []string, loadedWritable int) string {
	if index >= 0 && index < len(static) {
		return static[index]
	}
	return guardV3LookupPlaceholder(index, len(static), loadedWritable)
}

func guardV3LookupPlaceholder(index, staticCount, loadedWritable int) string {
	loadedIndex := index - staticCount
	if loadedIndex < 0 {
		return "unresolved-account:" + strconv.Itoa(index)
	}
	if loadedIndex < loadedWritable {
		return "lookup-writable:" + strconv.Itoa(loadedIndex)
	}
	return "lookup-readonly:" + strconv.Itoa(loadedIndex-loadedWritable)
}

func guardV3Base58Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	zeros := 0
	for zeros < len(data) && data[zeros] == 0 {
		zeros++
	}
	value := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	mod := new(big.Int)
	encoded := make([]byte, 0, len(data)*2)
	for value.Sign() > 0 {
		value.DivMod(value, base, mod)
		encoded = append(encoded, guardV3Base58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		encoded = append(encoded, guardV3Base58Alphabet[0])
	}
	for left, right := 0, len(encoded)-1; left < right; left, right = left+1, right-1 {
		encoded[left], encoded[right] = encoded[right], encoded[left]
	}
	return string(encoded)
}

func uniqueGuardV3Findings(values []transactionFirewallFinding) []transactionFirewallFinding {
	out := make([]transactionFirewallFinding, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		key := strings.TrimSpace(value.Code)
		if key == "" {
			key = value.Title + "|" + value.Evidence
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}

func removeGuardV3Finding(values []transactionFirewallFinding, code string) []transactionFirewallFinding {
	out := make([]transactionFirewallFinding, 0, len(values))
	for _, value := range values {
		if value.Code != code {
			out = append(out, value)
		}
	}
	return out
}

func removeGuardV3Limitation(values []string, target string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != target {
			out = append(out, value)
		}
	}
	return out
}

func guardV3IntValue(value *int) int {
	if value == nil {
		return -1
	}
	return *value
}

func compactGuardV3Evidence(value string) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if len(value) > 240 {
		value = value[:240]
	}
	return value
}
