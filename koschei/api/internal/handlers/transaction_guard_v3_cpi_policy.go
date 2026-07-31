package handlers

import (
	"context"
	"fmt"
	"strings"

	"koschei/api/internal/services"
)

const guardV3CPIControllerEvidenceLimit = 32

func resolveTransactionGuardV3CPIFlow(
	ctx context.Context,
	rpcURL string,
	decoded transactionGuardDecodedTransaction,
	wallet string,
	policyAccounts []transactionGuardAccount,
	expectedPrograms []string,
	requiredPrograms []string,
	groups []services.SolanaInnerInstructionGroup,
	preOrder, postOrder []string,
	pre, post []*services.SolanaAccountInfo,
) (transactionGuardCPIFlowAnalysis, []transactionFirewallFinding) {
	flow, findings := analyzeTransactionGuardV3CPIFlow(decoded, wallet, policyAccounts, groups, preOrder, postOrder, pre, post)
	controllers := transactionGuardV3CPIControllerAddresses(flow, wallet)
	if len(controllers) > 0 && strings.TrimSpace(rpcURL) != "" {
		controllerInfo, controllerOrder, err := services.SolanaGetMultipleAccountsBase64(ctx, rpcURL, controllers)
		if err != nil {
			flow.Complete = false
			flow.Status = "controller_evidence_unavailable"
			flow.Limitations = append(flow.Limitations, "Token-vault controller accounts could not be resolved; no protocol intermediary was treated as verified.")
			findings = append(findings, transactionFirewallFinding{
				Code: "cpi_controller_evidence_unavailable", Severity: "high",
				Title: "CPI token-vault controller evidence is unavailable",
				Evidence: compactGuardV3Evidence(err.Error()), Score: 0,
			})
		} else {
			enrichedPreOrder, enrichedPre := appendTransactionGuardV3CPIAccountEvidence(preOrder, pre, controllerOrder, controllerInfo.Value)
			enrichedPostOrder, enrichedPost := appendTransactionGuardV3CPIAccountEvidence(postOrder, post, controllerOrder, controllerInfo.Value)
			flow, findings = analyzeTransactionGuardV3CPIFlow(
				decoded, wallet, policyAccounts, groups,
				enrichedPreOrder, enrichedPostOrder, enrichedPre, enrichedPost,
			)
		}
	}
	return refineTransactionGuardV3CPIProgramPolicy(flow, findings, expectedPrograms, requiredPrograms)
}

func transactionGuardV3CPIControllerAddresses(flow transactionGuardCPIFlowAnalysis, wallet string) []string {
	wallet = strings.TrimSpace(wallet)
	out := []string{}
	seen := map[string]bool{}
	for _, account := range flow.Accounts {
		controller := strings.TrimSpace(account.TokenOwner)
		if account.Classification != "token_account" || controller == "" || controller == wallet || account.VaultCandidate {
			continue
		}
		if account.ControllerProgramOwner != "" {
			continue
		}
		if !looksLikeGuardPubkey(controller) || seen[controller] {
			continue
		}
		seen[controller] = true
		out = append(out, controller)
		if len(out) == guardV3CPIControllerEvidenceLimit {
			break
		}
	}
	return out
}

func appendTransactionGuardV3CPIAccountEvidence(
	order []string,
	values []*services.SolanaAccountInfo,
	additionalOrder []string,
	additionalValues []*services.SolanaAccountInfo,
) ([]string, []*services.SolanaAccountInfo) {
	outOrder := append([]string{}, order...)
	outValues := append([]*services.SolanaAccountInfo{}, values...)
	seen := map[string]bool{}
	for _, address := range outOrder {
		seen[address] = true
	}
	for index, address := range additionalOrder {
		address = strings.TrimSpace(address)
		if address == "" || seen[address] {
			continue
		}
		seen[address] = true
		outOrder = append(outOrder, address)
		if index < len(additionalValues) {
			outValues = append(outValues, additionalValues[index])
		} else {
			outValues = append(outValues, nil)
		}
	}
	return outOrder, outValues
}

func refineTransactionGuardV3CPIProgramPolicy(
	flow transactionGuardCPIFlowAnalysis,
	findings []transactionFirewallFinding,
	expectedPrograms []string,
	requiredPrograms []string,
) (transactionGuardCPIFlowAnalysis, []transactionFirewallFinding) {
	declaredPrograms := stringSet(normalizeGuardProgramList(append(append([]string{}, expectedPrograms...), requiredPrograms...)))
	if len(declaredPrograms) == 0 || len(flow.AssetMovements) == 0 {
		return flow, uniqueGuardV3Findings(findings)
	}
	accounts := map[string]transactionGuardCPIAccount{}
	for _, account := range flow.Accounts {
		accounts[account.Address] = account
	}

	removeFinding := map[string]bool{}
	unverified := map[string]bool{}
	actionableUndeclared := 0
	for index := range flow.AssetMovements {
		movement := &flow.AssetMovements[index]
		if !movement.WalletOrigin || !movement.UndeclaredByAccountPolicy || !declaredPrograms[movement.ParentProgramID] {
			if movement.WalletOrigin && movement.UndeclaredByAccountPolicy {
				actionableUndeclared++
			}
			continue
		}
		destination := accounts[movement.Destination]
		findingCode := "cpi_undeclared_wallet_exit_" + guardV3CompactAddressHash(movement.Destination)
		verifiedVault := destination.VaultCandidate && destination.ControllerProgramOwner == movement.ParentProgramID
		if verifiedVault {
			movement.UndeclaredByAccountPolicy = false
			removeFinding[findingCode] = true
			continue
		}
		controllerUnresolved := movement.AssetType == "token" && destination.Classification == "token_account" && destination.ControllerProgramOwner == ""
		if controllerUnresolved {
			movement.UndeclaredByAccountPolicy = false
			removeFinding[findingCode] = true
			unverified[movement.Destination] = true
			flow.Complete = false
			flow.Status = "protocol_intermediary_unverified"
			continue
		}
		actionableUndeclared++
	}
	flow.UndeclaredMovementCount = actionableUndeclared

	out := make([]transactionFirewallFinding, 0, len(findings)+len(unverified))
	for _, finding := range findings {
		if !removeFinding[finding.Code] {
			out = append(out, finding)
		}
	}
	for destination := range unverified {
		flow.Limitations = append(flow.Limitations,
			"A declared program moved wallet tokens to "+destination+", but the destination controller could not be verified as that program's PDA/vault.")
		out = append(out, transactionFirewallFinding{
			Code: "cpi_protocol_intermediary_unverified_" + guardV3CompactAddressHash(destination), Severity: "high",
			Title: "Declared program intermediary could not be verified",
			Evidence: compactGuardV3Evidence(fmt.Sprintf("destination=%s; safe decision withheld until controller ownership is verified", destination)), Score: 0,
		})
	}
	flow.Limitations = uniqueExplanationStrings(flow.Limitations)
	return flow, uniqueGuardV3Findings(out)
}
