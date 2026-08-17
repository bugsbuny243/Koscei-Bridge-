package executionproof

import "encoding/json"

// UnmarshalJSON decodes the Ethereum JSON-RPC transaction receipt wire shape.
// Ethereum clients use camelCase field names. The legacy snake_case aliases are
// accepted only to keep deterministic local fixtures backwards compatible; the
// canonical receipt is still normalized and rebound before authorization.
func (r *canonicalEVMReceipt) UnmarshalJSON(data []byte) error {
	type receiptWire struct {
		TransactionHash   string            `json:"transactionHash"`
		BlockHash         string            `json:"blockHash"`
		BlockNumber       string            `json:"blockNumber"`
		Status            string            `json:"status"`
		GasUsed           string            `json:"gasUsed"`
		CumulativeGasUsed string            `json:"cumulativeGasUsed"`
		ContractAddress   *string           `json:"contractAddress"`
		Logs              []json.RawMessage `json:"logs"`

		LegacyTransactionHash   string  `json:"transaction_hash"`
		LegacyBlockHash         string  `json:"block_hash"`
		LegacyBlockNumber       string  `json:"block_number"`
		LegacyGasUsed           string  `json:"gas_used"`
		LegacyCumulativeGasUsed string  `json:"cumulative_gas_used"`
		LegacyContractAddress   *string `json:"contract_address"`
	}

	var wire receiptWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.TransactionHash == "" {
		wire.TransactionHash = wire.LegacyTransactionHash
	}
	if wire.BlockHash == "" {
		wire.BlockHash = wire.LegacyBlockHash
	}
	if wire.BlockNumber == "" {
		wire.BlockNumber = wire.LegacyBlockNumber
	}
	if wire.GasUsed == "" {
		wire.GasUsed = wire.LegacyGasUsed
	}
	if wire.CumulativeGasUsed == "" {
		wire.CumulativeGasUsed = wire.LegacyCumulativeGasUsed
	}
	if wire.ContractAddress == nil {
		wire.ContractAddress = wire.LegacyContractAddress
	}

	r.TransactionHash = wire.TransactionHash
	r.BlockHash = wire.BlockHash
	r.BlockNumber = wire.BlockNumber
	r.Status = wire.Status
	r.GasUsed = wire.GasUsed
	r.CumulativeGasUsed = wire.CumulativeGasUsed
	r.ContractAddress = wire.ContractAddress
	r.Logs = wire.Logs
	return nil
}
