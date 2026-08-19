package executionproof

import "encoding/json"

// UnmarshalJSON accepts only the Ethereum JSON-RPC transaction receipt wire
// shape. Production evidence must not be normalized from non-standard aliases:
// if an RPC/provider does not return the canonical camelCase fields, the
// receipt identity check fails closed.
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
	}

	var wire receiptWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
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
