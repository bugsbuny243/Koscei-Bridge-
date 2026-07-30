package handlers

import (
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"testing"
)

func TestDecodeTransactionGuardV3LegacySOLTransfer(t *testing.T) {
	payer := guardV3TestKey(1)
	recipient := guardV3TestKey(2)
	system := guardV3TestBase58Decode(t, guardV3SystemProgramID)
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[:4], 2)
	binary.LittleEndian.PutUint64(data[4:], 1_250_000)
	tx := guardV3TestTransaction(false, [][]byte{payer, recipient, system}, []guardV3TestInstruction{{program: 2, accounts: []byte{0, 1}, data: data}}, nil)

	decoded, findings := decodeTransactionGuardV3(base64.StdEncoding.EncodeToString(tx), "base64", guardV3Base58Encode(payer))
	if !decoded.Available || !decoded.Complete || decoded.Version != "legacy" {
		t.Fatalf("unexpected decode status: %+v", decoded)
	}
	if decoded.FeePayer != guardV3Base58Encode(payer) {
		t.Fatalf("fee payer mismatch: %s", decoded.FeePayer)
	}
	if len(decoded.SOLTransfers) != 1 {
		t.Fatalf("expected one SOL transfer, got %d", len(decoded.SOLTransfers))
	}
	transfer := decoded.SOLTransfers[0]
	if transfer.Recipient != guardV3Base58Encode(recipient) || transfer.Lamports != "1250000" {
		t.Fatalf("unexpected transfer: %+v", transfer)
	}
	if decoded.DeclaredWalletSOLSpend != "1250000" || decoded.ExplicitSOLTransferLamports != "1250000" {
		t.Fatalf("unexpected SOL totals: %+v", decoded)
	}
	if !guardV3TestHasFinding(findings, "decoded_sol_transfer") {
		t.Fatalf("decoded SOL finding missing: %+v", findings)
	}
}

func TestDecodeTransactionGuardV3TokenApprove(t *testing.T) {
	owner := guardV3TestKey(3)
	source := guardV3TestKey(4)
	delegate := guardV3TestKey(5)
	tokenProgram := guardV3TestBase58Decode(t, guardV3SPLTokenProgramID)
	data := make([]byte, 9)
	data[0] = 4
	binary.LittleEndian.PutUint64(data[1:], 42_000)
	tx := guardV3TestTransaction(false, [][]byte{owner, source, delegate, tokenProgram}, []guardV3TestInstruction{{program: 3, accounts: []byte{1, 2, 0}, data: data}}, nil)

	decoded, findings := decodeTransactionGuardV3(base64.StdEncoding.EncodeToString(tx), "base64", guardV3Base58Encode(owner))
	if len(decoded.TokenOperations) != 1 {
		t.Fatalf("expected one token operation, got %d", len(decoded.TokenOperations))
	}
	operation := decoded.TokenOperations[0]
	if operation.Kind != "approve" || operation.AmountRaw != "42000" || operation.Delegate != guardV3Base58Encode(delegate) {
		t.Fatalf("unexpected approve operation: %+v", operation)
	}
	if !guardV3TestHasFinding(findings, "decoded_delegate_approval") {
		t.Fatalf("delegate approval finding missing: %+v", findings)
	}
}

func TestDecodeTransactionGuardV3VersionedLookupWithholdsCompleteness(t *testing.T) {
	payer := guardV3TestKey(6)
	system := guardV3TestBase58Decode(t, guardV3SystemProgramID)
	lookupTable := guardV3TestKey(7)
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[:4], 2)
	binary.LittleEndian.PutUint64(data[4:], 99)
	lookups := []guardV3TestLookup{{table: lookupTable, writable: []byte{3}, readonly: []byte{9}}}
	tx := guardV3TestTransaction(true, [][]byte{payer, system}, []guardV3TestInstruction{{program: 1, accounts: []byte{0, 2}, data: data}}, lookups)

	decoded, findings := decodeTransactionGuardV3(base64.StdEncoding.EncodeToString(tx), "base64", guardV3Base58Encode(payer))
	if !decoded.Available || decoded.Complete {
		t.Fatalf("versioned lookup must remain incomplete: %+v", decoded)
	}
	if decoded.UnresolvedLookupAccountCount != 2 || decoded.AddressLookupCount != 1 {
		t.Fatalf("unexpected lookup counts: %+v", decoded)
	}
	if len(decoded.SOLTransfers) != 1 || decoded.SOLTransfers[0].Recipient != "lookup-writable:0" {
		t.Fatalf("lookup recipient was not preserved: %+v", decoded.SOLTransfers)
	}
	if !guardV3TestHasFinding(findings, "transaction_address_lookup_unresolved") {
		t.Fatalf("lookup withhold finding missing: %+v", findings)
	}
}

type guardV3TestInstruction struct {
	program  byte
	accounts []byte
	data     []byte
}

type guardV3TestLookup struct {
	table    []byte
	writable []byte
	readonly []byte
}

func guardV3TestTransaction(versioned bool, accounts [][]byte, instructions []guardV3TestInstruction, lookups []guardV3TestLookup) []byte {
	out := guardV3TestShortVec(1)
	out = append(out, make([]byte, 64)...)
	if versioned {
		out = append(out, 0x80)
	}
	out = append(out, 1, 0, 1)
	out = append(out, guardV3TestShortVec(len(accounts))...)
	for _, account := range accounts {
		out = append(out, account...)
	}
	out = append(out, make([]byte, 32)...)
	out = append(out, guardV3TestShortVec(len(instructions))...)
	for _, instruction := range instructions {
		out = append(out, instruction.program)
		out = append(out, guardV3TestShortVec(len(instruction.accounts))...)
		out = append(out, instruction.accounts...)
		out = append(out, guardV3TestShortVec(len(instruction.data))...)
		out = append(out, instruction.data...)
	}
	if versioned {
		out = append(out, guardV3TestShortVec(len(lookups))...)
		for _, lookup := range lookups {
			out = append(out, lookup.table...)
			out = append(out, guardV3TestShortVec(len(lookup.writable))...)
			out = append(out, lookup.writable...)
			out = append(out, guardV3TestShortVec(len(lookup.readonly))...)
			out = append(out, lookup.readonly...)
		}
	}
	return out
}

func guardV3TestShortVec(value int) []byte {
	out := []byte{}
	for {
		current := byte(value & 0x7f)
		value >>= 7
		if value > 0 {
			current |= 0x80
		}
		out = append(out, current)
		if value == 0 {
			return out
		}
	}
}

func guardV3TestKey(seed byte) []byte {
	out := make([]byte, 32)
	for index := range out {
		out[index] = seed + byte(index)
	}
	return out
}

func guardV3TestBase58Decode(t *testing.T, value string) []byte {
	t.Helper()
	alphabet := map[byte]int64{}
	for index, character := range guardV3Base58Alphabet {
		alphabet[character] = int64(index)
	}
	number := big.NewInt(0)
	base := big.NewInt(58)
	for index := 0; index < len(value); index++ {
		digit, ok := alphabet[value[index]]
		if !ok {
			t.Fatalf("invalid base58 character %q", value[index])
		}
		number.Mul(number, base)
		number.Add(number, big.NewInt(digit))
	}
	decoded := number.Bytes()
	zeros := 0
	for zeros < len(value) && value[zeros] == guardV3Base58Alphabet[0] {
		zeros++
	}
	out := append(make([]byte, zeros), decoded...)
	if len(out) > 32 {
		t.Fatalf("decoded key exceeds 32 bytes")
	}
	if len(out) < 32 {
		out = append(make([]byte, 32-len(out)), out...)
	}
	return out
}

func guardV3TestHasFinding(findings []transactionFirewallFinding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
