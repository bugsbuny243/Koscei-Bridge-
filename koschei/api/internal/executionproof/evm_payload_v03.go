package executionproof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
)

// EVMPayload is the exact EVM action simulated by the v0.3 fork backend.
// Identity is derived from these raw fields; callers never provide an
// authoritative payload digest.
type EVMPayload struct {
	From     string `json:"from"`
	To       string `json:"to"`
	ValueHex string `json:"value"`
	DataHex  string `json:"data"`
}

func canonicalEVMPayload(input EVMPayload) (EVMPayload, bool) {
	from, ok := canonicalEVMAddress(input.From)
	if !ok {
		return EVMPayload{}, false
	}
	to, ok := canonicalEVMAddress(input.To)
	if !ok {
		return EVMPayload{}, false
	}
	value, ok := canonicalHexQuantity(input.ValueHex)
	if !ok {
		return EVMPayload{}, false
	}
	data, ok := canonicalHexBytes(input.DataHex)
	if !ok {
		return EVMPayload{}, false
	}
	return EVMPayload{From: from, To: to, ValueHex: value, DataHex: data}, true
}

func evmPayloadDigest(input EVMPayload) (string, bool) {
	canonical, ok := canonicalEVMPayload(input)
	if !ok {
		return "", false
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", false
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), true
}

func canonicalEVMAddress(value string) (string, bool) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
	if len(value) != 40 {
		return "", false
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", false
	}
	return "0x" + strings.ToLower(value), true
}

func canonicalHexQuantity(value string) (string, bool) {
	value = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x")
	if value == "" {
		return "", false
	}
	n := new(big.Int)
	if _, ok := n.SetString(value, 16); !ok || n.Sign() < 0 || n.BitLen() > 256 {
		return "", false
	}
	return "0x" + n.Text(16), true
}

func canonicalHexBytes(value string) (string, bool) {
	value = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x")
	if len(value)%2 != 0 {
		return "", false
	}
	if value != "" {
		if _, err := hex.DecodeString(value); err != nil {
			return "", false
		}
	}
	return "0x" + value, true
}
