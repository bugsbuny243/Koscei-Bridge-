package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"koschei/api/internal/services"
)

const transactionGuardStateWitnessVersion = "koschei-transaction-state-witness-v1"

type transactionGuardStateWitnessAccount struct {
	Address   string `json:"address"`
	Present   bool   `json:"present"`
	StateHash string `json:"state_hash"`
}

type transactionGuardStateWitness struct {
	Version                string                               `json:"version"`
	Status                 string                               `json:"status"`
	Complete               bool                                 `json:"complete"`
	TransactionFingerprint string                               `json:"transaction_fingerprint"`
	PreStateSlot           int64                                `json:"pre_state_slot,omitempty"`
	SimulationSlot         int64                                `json:"simulation_slot,omitempty"`
	SlotSpread             uint64                               `json:"slot_spread,omitempty"`
	AccountCount           int                                  `json:"account_count"`
	AccountRoot            string                               `json:"account_root_sha256,omitempty"`
	BindingHash            string                               `json:"binding_hash,omitempty"`
	Accounts               []transactionGuardStateWitnessAccount `json:"accounts"`
	Limitations            []string                             `json:"limitations"`
}

type transactionGuardStateLeaf struct {
	Present    bool `json:"present"`
	Lamports   int64 `json:"lamports,omitempty"`
	Owner      string `json:"owner,omitempty"`
	Executable bool `json:"executable,omitempty"`
	RentEpoch  any `json:"rent_epoch,omitempty"`
	Space      int64 `json:"space,omitempty"`
	Data       any `json:"data,omitempty"`
}

type transactionGuardStateRootLeaf struct {
	Address   string `json:"address"`
	StateHash string `json:"state_hash"`
}

type transactionGuardStateBinding struct {
	Version                string `json:"version"`
	TransactionFingerprint string `json:"transaction_fingerprint"`
	PreStateSlot           int64  `json:"pre_state_slot"`
	SimulationSlot         int64  `json:"simulation_slot"`
	AccountRoot            string `json:"account_root_sha256"`
}

func unavailableTransactionGuardStateWitness(fingerprint string, simulationSlot int64, reason string) transactionGuardStateWitness {
	limitations := []string{}
	if strings.TrimSpace(reason) != "" {
		limitations = append(limitations, strings.TrimSpace(reason))
	}
	return transactionGuardStateWitness{
		Version:                transactionGuardStateWitnessVersion,
		Status:                 "not_collected",
		Complete:               false,
		TransactionFingerprint: strings.TrimSpace(fingerprint),
		SimulationSlot:         simulationSlot,
		Accounts:               []transactionGuardStateWitnessAccount{},
		Limitations:            limitations,
	}
}

func buildTransactionGuardStateWitness(fingerprint string, preStateSlot, simulationSlot int64, addresses []string, accounts []*services.SolanaAccountInfo) transactionGuardStateWitness {
	out := transactionGuardStateWitness{
		Version:                transactionGuardStateWitnessVersion,
		Status:                 "incomplete",
		Complete:               false,
		TransactionFingerprint: strings.TrimSpace(fingerprint),
		PreStateSlot:           preStateSlot,
		SimulationSlot:         simulationSlot,
		Accounts:               []transactionGuardStateWitnessAccount{},
		Limitations:            []string{},
	}
	if preStateSlot > 0 && simulationSlot > 0 {
		if preStateSlot > simulationSlot {
			out.SlotSpread = uint64(preStateSlot - simulationSlot)
		} else {
			out.SlotSpread = uint64(simulationSlot - preStateSlot)
		}
	}
	if out.TransactionFingerprint == "" {
		out.Limitations = append(out.Limitations, "Transaction fingerprint is unavailable.")
	}
	if len(addresses) == 0 {
		out.Status = "not_collected"
		out.Limitations = append(out.Limitations, "No bounded account set was available for state witnessing.")
		return out
	}
	if len(addresses) != len(accounts) {
		out.Limitations = append(out.Limitations, "Pre-state account results do not align with the requested address set.")
		return out
	}
	if preStateSlot <= 0 {
		out.Limitations = append(out.Limitations, "Pre-state RPC context slot is unavailable.")
	}
	if simulationSlot <= 0 {
		out.Limitations = append(out.Limitations, "Simulation context slot is unavailable.")
	}

	rootLeaves := make([]transactionGuardStateRootLeaf, 0, len(addresses))
	seen := map[string]struct{}{}
	for index, rawAddress := range addresses {
		address := strings.TrimSpace(rawAddress)
		if address == "" {
			out.Limitations = append(out.Limitations, "State witness contains an empty account address.")
			continue
		}
		if _, exists := seen[address]; exists {
			out.Limitations = append(out.Limitations, "State witness contains a duplicate account address.")
			continue
		}
		seen[address] = struct{}{}
		hash, present, err := transactionGuardAccountStateHash(accounts[index])
		if err != nil {
			out.Limitations = append(out.Limitations, "Account state could not be canonicalized: "+address)
			continue
		}
		out.Accounts = append(out.Accounts, transactionGuardStateWitnessAccount{Address: address, Present: present, StateHash: hash})
		rootLeaves = append(rootLeaves, transactionGuardStateRootLeaf{Address: address, StateHash: hash})
	}
	sort.Slice(out.Accounts, func(i, j int) bool { return out.Accounts[i].Address < out.Accounts[j].Address })
	sort.Slice(rootLeaves, func(i, j int) bool { return rootLeaves[i].Address < rootLeaves[j].Address })
	out.AccountCount = len(out.Accounts)
	if len(rootLeaves) != len(addresses) {
		return out
	}
	rootPayload, err := json.Marshal(rootLeaves)
	if err != nil {
		out.Limitations = append(out.Limitations, "State witness root could not be encoded.")
		return out
	}
	rootDigest := sha256.Sum256(rootPayload)
	out.AccountRoot = hex.EncodeToString(rootDigest[:])
	binding := transactionGuardStateBinding{
		Version:                out.Version,
		TransactionFingerprint: out.TransactionFingerprint,
		PreStateSlot:           out.PreStateSlot,
		SimulationSlot:         out.SimulationSlot,
		AccountRoot:            out.AccountRoot,
	}
	bindingPayload, err := json.Marshal(binding)
	if err != nil {
		out.Limitations = append(out.Limitations, "State witness binding could not be encoded.")
		return out
	}
	bindingDigest := sha256.Sum256(bindingPayload)
	out.BindingHash = hex.EncodeToString(bindingDigest[:])
	if out.TransactionFingerprint == "" || preStateSlot <= 0 || simulationSlot <= 0 || len(out.Limitations) > 0 {
		return out
	}
	out.Status = "complete"
	out.Complete = true
	return out
}

func transactionGuardAccountStateHash(info *services.SolanaAccountInfo) (string, bool, error) {
	leaf := transactionGuardStateLeaf{Present: info != nil}
	if info != nil {
		leaf.Lamports = info.Lamports
		leaf.Owner = strings.TrimSpace(info.Owner)
		leaf.Executable = info.Executable
		leaf.RentEpoch = info.RentEpoch
		leaf.Space = info.Space
		leaf.Data = info.Data
	}
	payload, err := json.Marshal(leaf)
	if err != nil {
		return "", info != nil, err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), info != nil, nil
}
