package handlers

import (
	"fmt"
	"sort"
	"strconv"

	"koschei/api/internal/services"
)

func analyzeTransactionGuardV3AuthoritySurface(
	decoded transactionGuardDecodedTransaction,
	innerGroups []services.SolanaInnerInstructionGroup,
	snapshots transactionGuardAuthoritySnapshots,
) (transactionGuardAuthoritySurfaceAnalysis, []transactionFirewallFinding) {
	analysis := transactionGuardAuthoritySurfaceAnalysis{
		Requested:              true,
		Required:               envBool("TRANSACTION_GUARD_REQUIRE_AUTHORITY_SURFACE", true),
		Available:              decoded.Available,
		Complete:               decoded.Complete,
		Status:                 "none_observed",
		Events:                 []transactionGuardAuthorityEvent{},
		TransferHookProgramIDs: []string{},
		Limitations: []string{
			"Token-2022 extension instructions are decoded from the signed transaction and successful simulation path.",
			"Base SPL token-account and mint authority fields are verified from final simulated account state when RPC returns those accounts.",
		},
	}
	if !decoded.Available {
		analysis.Complete = false
		analysis.Status = "transaction_decode_unavailable"
		return analysis, transactionGuardAuthorityUnavailableFinding(analysis.Required, "serialized transaction could not be decoded")
	}

	instructions, unresolved := transactionGuardV3AuthorityInstructions(decoded, innerGroups)
	if unresolved > 0 {
		analysis.Complete = false
		analysis.Limitations = append(analysis.Limitations, fmt.Sprintf("%d authority-relevant instruction(s) could not be resolved.", unresolved))
	}
	findings := []transactionFirewallFinding{}
	hookPrograms := map[string]bool{}
	for _, instruction := range instructions {
		event, relevant, err := decodeTransactionGuardV3AuthorityEvent(instruction)
		if err != nil {
			analysis.Complete = false
			findings = append(findings, transactionFirewallFinding{
				Code:     "authority_instruction_unresolved_" + strconv.Itoa(instruction.Index) + "_" + strconv.Itoa(instruction.InnerSequence),
				Severity: guardV3RequiredSeverity(analysis.Required),
				Title:    "Authority-changing token instruction could not be fully decoded",
				Evidence: compactGuardV3Evidence(err.Error()), Score: 0,
			})
			continue
		}
		if !relevant {
			continue
		}
		enrichTransactionGuardV3AuthorityPostState(&event, snapshots)
		if guardV3AuthorityRequiresFinalState(event) && !event.PostStateAvailable {
			analysis.Complete = false
			analysis.Limitations = append(analysis.Limitations,
				"Final simulated state was unavailable for "+event.Kind+" on "+firstNonEmptyString(event.Account, event.Source, event.Mint)+".")
		}
		analysis.Events = append(analysis.Events, event)
		if event.Persistent {
			analysis.PersistentEventCount++
		}
		if event.MintWide {
			analysis.MintWideEventCount++
		}
		if event.ActiveAfterSimulation != nil && *event.ActiveAfterSimulation && (event.Kind == "approve" || event.Kind == "approve_checked") {
			analysis.ActiveDelegateCount++
		}
		if looksLikeGuardPubkey(event.TransferHookProgramID) {
			hookPrograms[event.TransferHookProgramID] = true
		}
		if finding, ok := transactionGuardV3AuthorityFinding(event); ok {
			findings = append(findings, finding)
		}
	}

	sort.SliceStable(analysis.Events, func(i, j int) bool {
		if analysis.Events[i].InstructionIndex != analysis.Events[j].InstructionIndex {
			return analysis.Events[i].InstructionIndex < analysis.Events[j].InstructionIndex
		}
		return analysis.Events[i].InnerSequence < analysis.Events[j].InnerSequence
	})
	analysis.EventCount = len(analysis.Events)
	analysis.TransferHookProgramIDs = mapKeysSorted(hookPrograms)
	if analysis.EventCount > 0 {
		analysis.Status = "complete"
	}
	if !analysis.Complete {
		analysis.Status = "partial"
	}
	analysis.Limitations = uniqueExplanationStrings(analysis.Limitations)
	return analysis, uniqueGuardV3Findings(findings)
}

func guardV3AuthorityRequiresFinalState(event transactionGuardAuthorityEvent) bool {
	switch event.Kind {
	case "approve", "approve_checked", "revoke":
		return true
	case "set_authority":
		return event.AuthorityType != nil && *event.AuthorityType >= 0 && *event.AuthorityType <= 3
	default:
		return false
	}
}

func transactionGuardV3AuthorityInstructions(decoded transactionGuardDecodedTransaction, innerGroups []services.SolanaInnerInstructionGroup) ([]transactionGuardAuthorityInstruction, int) {
	addresses := transactionGuardV3CombinedAddresses(decoded)
	out := []transactionGuardAuthorityInstruction{}
	unresolved := 0
	for index, parsed := range decoded.parsedInstructions {
		if parsed.ProgramIndex < 0 || parsed.ProgramIndex >= len(addresses) {
			continue
		}
		programID := addresses[parsed.ProgramIndex]
		if programID != guardV3SPLTokenProgramID && programID != guardV3Token2022ProgramID {
			continue
		}
		if len(parsed.Data) == 0 || !guardV3AuthorityOpcode(int(parsed.Data[0])) {
			continue
		}
		accounts, complete := guardV3ResolveAuthorityAccounts(parsed.AccountIndexes, addresses)
		if !complete {
			unresolved++
			continue
		}
		out = append(out, transactionGuardAuthorityInstruction{
			Source: "outer", Index: index, ProgramID: programID, Accounts: accounts, Data: append([]byte{}, parsed.Data...),
		})
	}
	innerSequence := 0
	for _, group := range innerGroups {
		parentProgram := ""
		if group.Index >= 0 && group.Index < len(decoded.Instructions) {
			parentProgram = decoded.Instructions[group.Index].ProgramID
		}
		for _, inner := range group.Instructions {
			if inner.ProgramIDIndex < 0 || inner.ProgramIDIndex >= len(addresses) {
				continue
			}
			programID := addresses[inner.ProgramIDIndex]
			if programID != guardV3SPLTokenProgramID && programID != guardV3Token2022ProgramID {
				continue
			}
			data, err := guardV3Base58DecodeVariable(inner.Data)
			if err != nil {
				unresolved++
				continue
			}
			if len(data) == 0 || !guardV3AuthorityOpcode(int(data[0])) {
				continue
			}
			accounts, complete := guardV3ResolveAuthorityAccounts(inner.Accounts, addresses)
			if !complete {
				unresolved++
				continue
			}
			innerSequence++
			out = append(out, transactionGuardAuthorityInstruction{
				Source: "cpi", Index: group.Index, InnerSequence: innerSequence,
				ParentProgramID: parentProgram, ProgramID: programID, Accounts: accounts, Data: data,
			})
		}
	}
	return out, unresolved
}

func guardV3ResolveAuthorityAccounts(indexes []int, addresses []string) ([]string, bool) {
	out := make([]string, 0, len(indexes))
	for _, index := range indexes {
		if index < 0 || index >= len(addresses) || !looksLikeGuardPubkey(addresses[index]) {
			return nil, false
		}
		out = append(out, addresses[index])
	}
	return out, true
}
