package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"koschei/api/internal/services"
)

const guardV3CPIMaxInstructions = 256

type transactionGuardCPIAccount struct {
	Address                string `json:"address"`
	Classification         string `json:"classification"`
	ProgramOwner           string `json:"program_owner,omitempty"`
	Mint                   string `json:"mint,omitempty"`
	TokenOwner             string `json:"token_owner,omitempty"`
	Controller             string `json:"controller,omitempty"`
	ControllerProgramOwner string `json:"controller_program_owner,omitempty"`
	ControlStatus          string `json:"control_status"`
	Signer                 bool   `json:"signer"`
	Writable               bool   `json:"writable"`
	Executable             bool   `json:"executable"`
	PDACandidate           bool   `json:"pda_candidate"`
	PDAStatus              string `json:"pda_status"`
	VaultCandidate         bool   `json:"vault_candidate"`
	EvidenceStatus         string `json:"evidence_status"`
}

type transactionGuardCPIAssetMovement struct {
	AssetType                 string `json:"asset_type"`
	Kind                      string `json:"kind"`
	Source                    string `json:"source,omitempty"`
	Destination               string `json:"destination,omitempty"`
	Mint                      string `json:"mint,omitempty"`
	AmountRaw                 string `json:"amount_raw,omitempty"`
	Decimals                  *int   `json:"decimals,omitempty"`
	ProgramID                 string `json:"program_id"`
	ParentProgramID           string `json:"parent_program_id,omitempty"`
	ParentInstructionIndex    int    `json:"parent_instruction_index"`
	Sequence                  int    `json:"sequence"`
	StackHeight               *int   `json:"stack_height,omitempty"`
	SourceClassification      string `json:"source_classification,omitempty"`
	DestinationClassification string `json:"destination_classification,omitempty"`
	SourceController          string `json:"source_controller,omitempty"`
	DestinationController     string `json:"destination_controller,omitempty"`
	WalletOrigin              bool   `json:"wallet_origin"`
	InnerOnly                 bool   `json:"inner_only"`
	PolicyCompared            bool   `json:"policy_compared"`
	DeclaredByAccountPolicy   bool   `json:"declared_by_account_policy"`
	UndeclaredByAccountPolicy bool   `json:"undeclared_by_account_policy"`
	EvidenceStatus            string `json:"evidence_status"`
}

type transactionGuardCPIInstruction struct {
	Sequence               int      `json:"sequence"`
	ParentInstructionIndex int      `json:"parent_instruction_index"`
	ParentProgramID        string   `json:"parent_program_id,omitempty"`
	ProgramID              string   `json:"program_id,omitempty"`
	ProgramResolved        bool     `json:"program_resolved"`
	AccountIndexes         []int    `json:"account_indexes"`
	Accounts               []string `json:"accounts"`
	AccountsResolved       bool     `json:"accounts_resolved"`
	StackHeight            *int     `json:"stack_height,omitempty"`
	DataLength             int      `json:"data_length"`
	DataPrefixHex          string   `json:"data_prefix_hex,omitempty"`
	Kind                   string   `json:"kind"`
	ResolutionStatus       string   `json:"resolution_status"`
}

type transactionGuardCPIGroup struct {
	ParentInstructionIndex int                              `json:"parent_instruction_index"`
	ParentProgramID        string                           `json:"parent_program_id,omitempty"`
	Instructions           []transactionGuardCPIInstruction `json:"instructions"`
}

type transactionGuardCPIFlowAnalysis struct {
	Requested                  bool                               `json:"requested"`
	Required                   bool                               `json:"required"`
	Available                  bool                               `json:"available"`
	Complete                   bool                               `json:"complete"`
	Status                     string                             `json:"status"`
	OuterInstructionGroupCount int                                `json:"outer_instruction_group_count"`
	InnerInstructionCount      int                                `json:"inner_instruction_count"`
	UnresolvedInstructionCount int                                `json:"unresolved_instruction_count"`
	WalletOriginMovementCount  int                                `json:"wallet_origin_movement_count"`
	UndeclaredMovementCount    int                                `json:"undeclared_movement_count"`
	ProgramIDs                 []string                           `json:"program_ids"`
	Groups                     []transactionGuardCPIGroup         `json:"groups"`
	AssetMovements             []transactionGuardCPIAssetMovement `json:"asset_movements"`
	Accounts                   []transactionGuardCPIAccount       `json:"accounts"`
	Limitations                []string                           `json:"limitations"`
}

func unavailableTransactionGuardV3CPIFlow() transactionGuardCPIFlowAnalysis {
	return transactionGuardCPIFlowAnalysis{
		Requested:  true,
		Required:   envBool("TRANSACTION_GUARD_REQUIRE_CPI_FLOW", true),
		Available:  false,
		Complete:   false,
		Status:     "simulation_unavailable",
		ProgramIDs: []string{}, Groups: []transactionGuardCPIGroup{},
		AssetMovements: []transactionGuardCPIAssetMovement{}, Accounts: []transactionGuardCPIAccount{},
		Limitations: []string{"CPI and inner-instruction evidence requires a successful Solana simulation response."},
	}
}

func analyzeTransactionGuardV3CPIFlow(
	decoded transactionGuardDecodedTransaction,
	wallet string,
	policyAccounts []transactionGuardAccount,
	groups []services.SolanaInnerInstructionGroup,
	preOrder, postOrder []string,
	pre, post []*services.SolanaAccountInfo,
) (transactionGuardCPIFlowAnalysis, []transactionFirewallFinding) {
	analysis := transactionGuardCPIFlowAnalysis{
		Requested:  true,
		Required:   envBool("TRANSACTION_GUARD_REQUIRE_CPI_FLOW", true),
		Available:  true,
		Complete:   true,
		Status:     "none_observed",
		ProgramIDs: []string{}, Groups: []transactionGuardCPIGroup{},
		AssetMovements: []transactionGuardCPIAssetMovement{}, Accounts: []transactionGuardCPIAccount{},
		Limitations: []string{
			"PDA classification is heuristic unless seed derivation evidence is available.",
			"A program-owned non-signer account is reported as a PDA candidate, not as cryptographic proof of PDA derivation.",
		},
	}
	if len(groups) == 0 {
		return analysis, nil
	}

	addresses := transactionGuardV3CombinedAddresses(decoded)
	metadata := transactionGuardV3AccountMetadata(decoded)
	usedAddresses := map[string]bool{}
	programSet := map[string]bool{}
	instructionCount := 0
	findings := []transactionFirewallFinding{}
	policySet := map[string]bool{}
	for _, account := range policyAccounts {
		address := strings.TrimSpace(account.Address)
		if address != "" {
			policySet[address] = true
		}
	}
	policyCompared := len(policySet) > 0

	outerSOL := map[string]bool{}
	for _, transfer := range decoded.SOLTransfers {
		outerSOL[cpiSOLMovementKey(transfer.Source, transfer.Recipient, transfer.Lamports)] = true
	}
	outerToken := map[string]bool{}
	for _, operation := range decoded.TokenOperations {
		if operation.Kind == "transfer" || operation.Kind == "transfer_checked" {
			outerToken[cpiTokenMovementKey(operation.Source, operation.Destination, operation.Mint, operation.AmountRaw)] = true
		}
	}

	for _, sourceGroup := range groups {
		parentProgram := ""
		if sourceGroup.Index >= 0 && sourceGroup.Index < len(decoded.Instructions) {
			parentProgram = decoded.Instructions[sourceGroup.Index].ProgramID
		}
		group := transactionGuardCPIGroup{
			ParentInstructionIndex: sourceGroup.Index,
			ParentProgramID:        parentProgram,
			Instructions:           []transactionGuardCPIInstruction{},
		}
		for _, rawInstruction := range sourceGroup.Instructions {
			if instructionCount >= guardV3CPIMaxInstructions {
				analysis.Complete = false
				analysis.Status = "instruction_limit_exceeded"
				analysis.Limitations = append(analysis.Limitations, fmt.Sprintf("Only the first %d inner instructions were analyzed.", guardV3CPIMaxInstructions))
				break
			}
			instructionCount++
			instruction := transactionGuardCPIInstruction{
				Sequence: instructionCount - 1, ParentInstructionIndex: sourceGroup.Index,
				ParentProgramID: parentProgram, AccountIndexes: append([]int{}, rawInstruction.Accounts...),
				Accounts: []string{}, StackHeight: rawInstruction.StackHeight,
				Kind: "unclassified", ResolutionStatus: "complete",
			}

			if rawInstruction.ProgramIDIndex >= 0 && rawInstruction.ProgramIDIndex < len(addresses) && strings.TrimSpace(addresses[rawInstruction.ProgramIDIndex]) != "" {
				instruction.ProgramID = addresses[rawInstruction.ProgramIDIndex]
				instruction.ProgramResolved = true
				programSet[instruction.ProgramID] = true
				usedAddresses[instruction.ProgramID] = true
			} else {
				instruction.ResolutionStatus = "program_index_unresolved"
				analysis.UnresolvedInstructionCount++
				analysis.Complete = false
			}

			instruction.AccountsResolved = true
			for _, accountIndex := range rawInstruction.Accounts {
				if accountIndex < 0 || accountIndex >= len(addresses) || strings.TrimSpace(addresses[accountIndex]) == "" {
					instruction.Accounts = append(instruction.Accounts, fmt.Sprintf("unresolved-account:%d", accountIndex))
					instruction.AccountsResolved = false
					continue
				}
				address := addresses[accountIndex]
				instruction.Accounts = append(instruction.Accounts, address)
				usedAddresses[address] = true
			}
			if !instruction.AccountsResolved {
				if instruction.ResolutionStatus == "complete" {
					instruction.ResolutionStatus = "account_index_unresolved"
				}
				analysis.UnresolvedInstructionCount++
				analysis.Complete = false
			}

			data, dataErr := guardV3Base58DecodeVariable(rawInstruction.Data)
			if dataErr != nil {
				if instruction.ResolutionStatus == "complete" {
					instruction.ResolutionStatus = "instruction_data_unresolved"
				}
				analysis.UnresolvedInstructionCount++
				analysis.Complete = false
			} else {
				instruction.DataLength = len(data)
				prefix := data
				if len(prefix) > 12 {
					prefix = prefix[:12]
				}
				instruction.DataPrefixHex = hex.EncodeToString(prefix)
				if instruction.ProgramResolved && instruction.AccountsResolved {
					scratch := transactionGuardDecodedTransaction{}
					instruction.Kind = classifyTransactionGuardV3Instruction(instruction.ProgramID, instruction.Accounts, data, &scratch)
					for _, transfer := range scratch.SOLTransfers {
						movement := transactionGuardCPIAssetMovement{
							AssetType: "SOL", Kind: transfer.Kind, Source: transfer.Source, Destination: transfer.Recipient,
							AmountRaw: transfer.Lamports, ProgramID: instruction.ProgramID, ParentProgramID: parentProgram,
							ParentInstructionIndex: sourceGroup.Index, Sequence: instruction.Sequence, StackHeight: rawInstruction.StackHeight,
							PolicyCompared: policyCompared, DeclaredByAccountPolicy: policySet[transfer.Recipient], EvidenceStatus: "decoded_inner_instruction",
						}
						movement.InnerOnly = !outerSOL[cpiSOLMovementKey(movement.Source, movement.Destination, movement.AmountRaw)]
						analysis.AssetMovements = append(analysis.AssetMovements, movement)
					}
					for _, operation := range scratch.TokenOperations {
						if operation.Kind != "transfer" && operation.Kind != "transfer_checked" {
							continue
						}
						movement := transactionGuardCPIAssetMovement{
							AssetType: "token", Kind: operation.Kind, Source: operation.Source, Destination: operation.Destination,
							Mint: operation.Mint, AmountRaw: operation.AmountRaw, Decimals: operation.Decimals,
							ProgramID: instruction.ProgramID, ParentProgramID: parentProgram,
							ParentInstructionIndex: sourceGroup.Index, Sequence: instruction.Sequence, StackHeight: rawInstruction.StackHeight,
							PolicyCompared: policyCompared, DeclaredByAccountPolicy: policySet[operation.Destination], EvidenceStatus: "decoded_inner_instruction",
						}
						movement.InnerOnly = !outerToken[cpiTokenMovementKey(movement.Source, movement.Destination, movement.Mint, movement.AmountRaw)]
						analysis.AssetMovements = append(analysis.AssetMovements, movement)
					}
				}
			}
			group.Instructions = append(group.Instructions, instruction)
		}
		analysis.Groups = append(analysis.Groups, group)
		if instructionCount >= guardV3CPIMaxInstructions {
			break
		}
	}

	analysis.OuterInstructionGroupCount = len(analysis.Groups)
	analysis.InnerInstructionCount = instructionCount
	analysis.ProgramIDs = mapKeysSorted(programSet)
	analysis.Accounts = classifyTransactionGuardV3CPIAccounts(usedAddresses, metadata, wallet, preOrder, postOrder, pre, post)
	roleByAddress := map[string]transactionGuardCPIAccount{}
	for _, account := range analysis.Accounts {
		roleByAddress[account.Address] = account
	}

	undeclaredDestinations := map[string]bool{}
	walletDestinations := map[string]bool{}
	innerOnlyWalletMovement := false
	for index := range analysis.AssetMovements {
		movement := &analysis.AssetMovements[index]
		sourceRole := roleByAddress[movement.Source]
		destinationRole := roleByAddress[movement.Destination]
		movement.SourceClassification = sourceRole.Classification
		movement.DestinationClassification = destinationRole.Classification
		movement.SourceController = firstNonEmptyString(sourceRole.TokenOwner, sourceRole.Controller)
		movement.DestinationController = firstNonEmptyString(destinationRole.TokenOwner, destinationRole.Controller)
		movement.WalletOrigin = strings.TrimSpace(wallet) != "" && (movement.Source == wallet || sourceRole.TokenOwner == wallet)
		if movement.WalletOrigin {
			analysis.WalletOriginMovementCount++
			walletDestinations[movement.Destination] = true
			if movement.InnerOnly {
				innerOnlyWalletMovement = true
			}
			movement.UndeclaredByAccountPolicy = movement.PolicyCompared && !movement.DeclaredByAccountPolicy
			if movement.UndeclaredByAccountPolicy {
				analysis.UndeclaredMovementCount++
				undeclaredDestinations[movement.Destination] = true
			}
		}
		if movement.Mint == "" && movement.AssetType == "token" {
			movement.Mint = firstNonEmptyString(sourceRole.Mint, destinationRole.Mint)
		}
	}

	if analysis.Complete {
		analysis.Status = "complete"
	} else if analysis.Status == "none_observed" {
		analysis.Status = "partial"
	}
	if analysis.UnresolvedInstructionCount > 0 {
		severity := "info"
		if analysis.Required {
			severity = "high"
		}
		findings = append(findings, transactionFirewallFinding{
			Code: "cpi_flow_incomplete", Severity: severity,
			Title:    "CPI asset-flow evidence is incomplete",
			Evidence: fmt.Sprintf("unresolved_inner_instructions=%d total_inner_instructions=%d", analysis.UnresolvedInstructionCount, analysis.InnerInstructionCount), Score: 0,
		})
	}
	for destination := range undeclaredDestinations {
		findings = append(findings, transactionFirewallFinding{
			Code: "cpi_undeclared_wallet_exit_" + guardV3CompactAddressHash(destination), Severity: "high",
			Title:    "Inner instruction sends wallet assets to an undeclared destination",
			Evidence: compactGuardV3Evidence(fmt.Sprintf("destination=%s policy_accounts=%d", destination, len(policySet))), Score: 50,
		})
	}
	if innerOnlyWalletMovement {
		findings = append(findings, transactionFirewallFinding{
			Code: "cpi_inner_only_wallet_movement", Severity: "info",
			Title:    "Wallet asset movement occurs inside CPI execution",
			Evidence: fmt.Sprintf("wallet_origin_movements=%d destinations=%d", analysis.WalletOriginMovementCount, len(walletDestinations)), Score: 0,
		})
	}
	vaultCount := 0
	for _, account := range analysis.Accounts {
		if account.VaultCandidate {
			vaultCount++
		}
	}
	if vaultCount > 0 {
		findings = append(findings, transactionFirewallFinding{
			Code: "cpi_program_controlled_vault_candidates", Severity: "info",
			Title:    "Program-controlled vault candidates participate in CPI flow",
			Evidence: fmt.Sprintf("vault_candidates=%d", vaultCount), Score: 0,
		})
	}
	return analysis, uniqueGuardV3Findings(findings)
}

func transactionGuardV3CombinedAddresses(decoded transactionGuardDecodedTransaction) []string {
	maxIndex := -1
	for _, account := range append(append([]transactionGuardDecodedAccount{}, decoded.StaticAccounts...), decoded.LoadedAccounts...) {
		if account.Index > maxIndex {
			maxIndex = account.Index
		}
	}
	if maxIndex < 0 {
		return []string{}
	}
	out := make([]string, maxIndex+1)
	for _, account := range decoded.StaticAccounts {
		if account.Index >= 0 && account.Index < len(out) {
			out[account.Index] = account.Address
		}
	}
	for _, account := range decoded.LoadedAccounts {
		if account.Index >= 0 && account.Index < len(out) {
			out[account.Index] = account.Address
		}
	}
	return out
}

func transactionGuardV3AccountMetadata(decoded transactionGuardDecodedTransaction) map[string]transactionGuardDecodedAccount {
	out := map[string]transactionGuardDecodedAccount{}
	for _, account := range append(append([]transactionGuardDecodedAccount{}, decoded.StaticAccounts...), decoded.LoadedAccounts...) {
		if strings.TrimSpace(account.Address) != "" {
			out[account.Address] = account
		}
	}
	return out
}

func classifyTransactionGuardV3CPIAccounts(
	used map[string]bool,
	metadata map[string]transactionGuardDecodedAccount,
	wallet string,
	preOrder, postOrder []string,
	pre, post []*services.SolanaAccountInfo,
) []transactionGuardCPIAccount {
	addresses := make([]string, 0, len(used))
	for address := range used {
		if looksLikeGuardPubkey(address) {
			addresses = append(addresses, address)
		}
	}
	sort.Strings(addresses)
	preIndex := addressIndex(preOrder)
	postIndex := addressIndex(postOrder)
	out := make([]transactionGuardCPIAccount, 0, len(addresses))
	for _, address := range addresses {
		meta := metadata[address]
		account := transactionGuardCPIAccount{
			Address: address, Signer: meta.Signer, Writable: meta.Writable,
			Classification: "unresolved_account", ControlStatus: "unresolved", PDAStatus: "not_evaluated", EvidenceStatus: "not_observed",
		}
		info := cpiAccountSnapshot(address, postIndex, post)
		if info == nil {
			info = cpiAccountSnapshot(address, preIndex, pre)
		}
		if info != nil {
			account.ProgramOwner = strings.TrimSpace(info.Owner)
			account.Executable = info.Executable
			account.EvidenceStatus = "verified_rpc_account_snapshot"
			switch {
			case info.Executable:
				account.Classification = "program"
				account.ControlStatus = "executable_program"
			case info.Owner == guardV3SPLTokenProgramID || info.Owner == guardV3Token2022ProgramID:
				account.Classification = "token_account"
				if snapshot, err := services.SolanaTokenAccountSnapshotFromInfo(info); err == nil {
					account.Mint = guardV3Base58Encode(snapshot.Mint[:])
					account.TokenOwner = guardV3Base58Encode(snapshot.Owner[:])
					account.Controller = account.TokenOwner
					if account.TokenOwner == strings.TrimSpace(wallet) {
						account.ControlStatus = "wallet_controlled_token_account"
					} else {
						account.ControlStatus = "external_token_controller"
					}
				} else {
					account.ControlStatus = "token_account_parse_failed"
				}
			case info.Owner == guardV3SystemProgramID || strings.TrimSpace(info.Owner) == "":
				account.Classification = "system_account"
				account.ControlStatus = "system_owned"
			default:
				account.Classification = "program_owned_account"
				account.ControllerProgramOwner = info.Owner
				account.ControlStatus = "program_owned"
				if !account.Signer {
					account.PDACandidate = true
					account.PDAStatus = "heuristic_program_owned_non_signer"
				}
			}
		}
		out = append(out, account)
	}

	byAddress := map[string]int{}
	for index := range out {
		byAddress[out[index].Address] = index
	}
	for index := range out {
		account := &out[index]
		if account.Classification != "token_account" || account.TokenOwner == "" || account.TokenOwner == strings.TrimSpace(wallet) {
			continue
		}
		controllerIndex, ok := byAddress[account.TokenOwner]
		if !ok {
			account.ControlStatus = "external_token_controller_unresolved"
			continue
		}
		controller := out[controllerIndex]
		account.ControllerProgramOwner = controller.ProgramOwner
		if controller.Classification == "program_owned_account" && controller.PDACandidate {
			account.VaultCandidate = true
			account.ControlStatus = "program_controlled_vault_candidate"
		}
	}
	return out
}

func cpiAccountSnapshot(address string, index map[string]int, values []*services.SolanaAccountInfo) *services.SolanaAccountInfo {
	position, ok := index[address]
	if !ok || position < 0 || position >= len(values) {
		return nil
	}
	return values[position]
}

func transactionGuardV3ThreatDecodedWithCPI(decoded transactionGuardDecodedTransaction, cpi transactionGuardCPIFlowAnalysis, wallet string) transactionGuardDecodedTransaction {
	out := decoded
	out.ProgramIDs = normalizeGuardProgramList(append(out.ProgramIDs, cpi.ProgramIDs...))
	for _, movement := range cpi.AssetMovements {
		switch movement.AssetType {
		case "SOL":
			out.SOLTransfers = append(out.SOLTransfers, transactionGuardDecodedSOLTransfer{
				Kind: "cpi_" + movement.Kind, Source: movement.Source, Recipient: movement.Destination, Lamports: movement.AmountRaw,
			})
		case "token":
			authority := ""
			if movement.WalletOrigin {
				authority = strings.TrimSpace(wallet)
			}
			out.TokenOperations = append(out.TokenOperations, transactionGuardDecodedTokenOperation{
				Kind: "transfer_checked", ProgramID: movement.ProgramID, Source: movement.Source,
				Destination: movement.Destination, Mint: movement.Mint, Authority: authority,
				AmountRaw: movement.AmountRaw, Decimals: movement.Decimals,
			})
		}
	}
	return out
}

func guardV3Base58DecodeVariable(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return []byte{}, nil
	}
	result := big.NewInt(0)
	base := big.NewInt(58)
	for _, char := range value {
		index := strings.IndexRune(string(guardV3Base58Alphabet), char)
		if index < 0 {
			return nil, fmt.Errorf("invalid base58 character")
		}
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(index)))
	}
	leadingZeros := 0
	for leadingZeros < len(value) && value[leadingZeros] == '1' {
		leadingZeros++
	}
	decoded := result.Bytes()
	out := make([]byte, leadingZeros+len(decoded))
	copy(out[leadingZeros:], decoded)
	return out, nil
}

func cpiSOLMovementKey(source, destination, amount string) string {
	return strings.TrimSpace(source) + "|" + strings.TrimSpace(destination) + "|" + strings.TrimSpace(amount)
}

func cpiTokenMovementKey(source, destination, mint, amount string) string {
	return strings.TrimSpace(source) + "|" + strings.TrimSpace(destination) + "|" + strings.TrimSpace(mint) + "|" + strings.TrimSpace(amount)
}

func guardV3CompactAddressHash(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:6])
}

func mapKeysSorted(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
