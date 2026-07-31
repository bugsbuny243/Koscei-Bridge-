package handlers

import (
	"fmt"
	"strconv"
	"strings"
)

func guardV3AuthorityTypeSemantics(authorityType int) (name, scope string, mintWide, canTransfer, canBurn bool) {
	types := []struct {
		name, scope string
		mintWide, canTransfer, canBurn bool
	}{
		{"mint_tokens", "mint_supply", true, false, false},
		{"freeze_account", "all_token_accounts_for_mint", true, false, false},
		{"account_owner", "single_token_account", false, true, false},
		{"close_account", "single_token_account", false, false, false},
		{"transfer_fee_config", "all_future_transfers_for_mint", true, false, false},
		{"withheld_withdraw", "withheld_transfer_fees_for_mint", true, false, false},
		{"close_mint", "mint_account", true, false, false},
		{"interest_rate", "ui_amount_for_mint", true, false, false},
		{"permanent_delegate", "all_token_accounts_for_mint", true, true, true},
		{"confidential_transfer_mint", "confidential_transfers_for_mint", true, false, false},
		{"transfer_hook_program_id", "all_future_transfers_for_mint", true, false, false},
		{"confidential_transfer_fee_config", "confidential_transfer_fees_for_mint", true, false, false},
		{"metadata_pointer", "metadata_pointer_for_mint", true, false, false},
		{"group_pointer", "group_pointer_for_mint", true, false, false},
		{"group_member_pointer", "group_member_pointer_for_mint", true, false, false},
		{"scaled_ui_amount", "ui_amount_for_mint", true, false, false},
		{"pause", "minting_transfers_and_burning_for_mint", true, false, false},
		{"permissioned_burn", "permissioned_burn_for_mint", true, false, true},
	}
	if authorityType < 0 || authorityType >= len(types) {
		return "unknown_authority_type_" + strconv.Itoa(authorityType), "unknown", false, false, false
	}
	value := types[authorityType]
	return value.name, value.scope, value.mintWide, value.canTransfer, value.canBurn
}

func guardV3AuthorityTypeExplanation(authorityType int, newAuthority string) string {
	name, scope, _, canTransfer, canBurn := guardV3AuthorityTypeSemantics(authorityType)
	if newAuthority == "revoked" {
		return fmt.Sprintf("The %s authority is revoked for scope %s.", name, scope)
	}
	capability := "controls " + strings.ReplaceAll(name, "_", " ")
	if canTransfer && canBurn {
		capability = "may transfer or burn tokens across the mint"
	} else if canTransfer {
		capability = "controls transfers from the token account"
	} else if canBurn {
		capability = "may authorize token burns"
	}
	return fmt.Sprintf("The new authority %s %s; scope=%s.", newAuthority, capability, scope)
}

func transactionGuardV3AuthorityFinding(event transactionGuardAuthorityEvent) (transactionFirewallFinding, bool) {
	finding := transactionFirewallFinding{Evidence: compactGuardV3Evidence(guardV3AuthorityEvidence(event))}
	switch event.Kind {
	case "approve", "approve_checked":
		if event.ActiveAfterSimulation != nil && !*event.ActiveAfterSimulation {
			return transactionFirewallFinding{}, false
		}
		finding.Code, finding.Severity, finding.Title, finding.Score = "authority_delegate_approval_"+guardV3CompactAddressHash(event.Account), "medium", "Token spending delegation remains after signing", 18
		if event.EffectivelyUnlimited {
			finding.Severity, finding.Title, finding.Score = "high", "Maximum-size token delegation", 35
		}
	case "initialize_permanent_delegate":
		finding.Code, finding.Severity, finding.Title, finding.Score = "authority_permanent_delegate_"+guardV3CompactAddressHash(event.Mint), "critical", "Mint-wide permanent delegate capability", 75
	case "set_authority":
		if event.NewAuthority == "revoked" || event.ActiveAfterSimulation != nil && !*event.ActiveAfterSimulation || event.AuthorityType == nil {
			return transactionFirewallFinding{}, false
		}
		finding.Code = "authority_change_" + event.AuthorityTypeName + "_" + guardV3CompactAddressHash(event.Account)
		finding.Severity, finding.Title, finding.Score = "high", "Persistent token authority change", 35
		if *event.AuthorityType == 8 || *event.AuthorityType == 16 || *event.AuthorityType == 17 {
			finding.Severity, finding.Title, finding.Score = "critical", "Critical mint-wide authority capability", 75
		}
	case "initialize_transfer_hook", "update_transfer_hook":
		if event.TransferHookProgramID == "revoked" {
			return transactionFirewallFinding{}, false
		}
		finding.Code, finding.Severity, finding.Title, finding.Score = "authority_transfer_hook_"+guardV3CompactAddressHash(event.Mint), "high", "Mint-wide transfer hook program configured", 35
	case "initialize_transfer_fee_config", "set_transfer_fee":
		if event.TransferFeeBasisPoints == nil || *event.TransferFeeBasisPoints == 0 {
			return transactionFirewallFinding{}, false
		}
		finding.Code, finding.Severity, finding.Title, finding.Score = "authority_transfer_fee_"+guardV3CompactAddressHash(event.Mint), "medium", "Mint-wide transfer fee configured", 25
		if *event.TransferFeeBasisPoints > 1000 {
			finding.Severity, finding.Title, finding.Score = "high", "Transfer fee exceeds 10%", 50
		}
	case "withdraw_withheld_tokens_from_mint", "withdraw_withheld_tokens_from_accounts":
		finding.Code, finding.Severity, finding.Title, finding.Score = "authority_withheld_fee_withdrawal_"+guardV3CompactAddressHash(event.Mint), "medium", "Withheld transfer fees are withdrawn", 20
	default:
		return transactionFirewallFinding{}, false
	}
	return finding, true
}

func guardV3AuthorityEvidence(event transactionGuardAuthorityEvent) string {
	parts := []string{"kind=" + event.Kind, "scope=" + event.Scope}
	for _, value := range []struct{ key, value string }{
		{"account", event.Account}, {"mint", event.Mint}, {"delegate", event.Delegate},
		{"new_authority", event.NewAuthority}, {"amount_raw", event.AmountRaw},
		{"hook_program", event.TransferHookProgramID}, {"maximum_fee_raw", event.MaximumFeeRaw},
	} {
		if value.value != "" {
			parts = append(parts, value.key+"="+value.value)
		}
	}
	if event.TransferFeeBasisPoints != nil {
		parts = append(parts, "fee_bps="+strconv.Itoa(*event.TransferFeeBasisPoints))
	}
	if event.ActiveAfterSimulation != nil {
		parts = append(parts, "active_after_simulation="+strconv.FormatBool(*event.ActiveAfterSimulation))
	}
	return strings.Join(parts, " ")
}

func transactionGuardAuthorityUnavailableFinding(required bool, evidence string) []transactionFirewallFinding {
	return []transactionFirewallFinding{{
		Code: "authority_surface_unavailable", Severity: guardV3RequiredSeverity(required),
		Title: "Token authority surface is unavailable", Evidence: compactGuardV3Evidence(evidence), Score: 0,
	}}
}

func guardV3RequiredSeverity(required bool) string {
	if required {
		return "high"
	}
	return "info"
}
