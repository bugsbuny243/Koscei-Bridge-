package handlers

import (
	"encoding/json"
	"fmt"
	"strings"

	"koschei/api/internal/services"
)

func unifiedProgramSecuritySurface(source map[string]any) services.ProgramSecuritySurface {
	fallback := newProgramSecuritySurface("not_requested")
	if source == nil {
		return fallback
	}
	raw, exists := source["program_security"]
	if !exists || raw == nil {
		return fallback
	}
	switch value := raw.(type) {
	case services.ProgramSecuritySurface:
		return value
	case *services.ProgramSecuritySurface:
		if value != nil {
			return *value
		}
		return fallback
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		fallback.Status = "projection_failed"
		fallback.Limitations = append(fallback.Limitations, "Program security evidence could not be projected into the unified report.")
		return fallback
	}
	var projected services.ProgramSecuritySurface
	if err := json.Unmarshal(encoded, &projected); err != nil {
		fallback.Status = "projection_failed"
		fallback.Limitations = append(fallback.Limitations, "Program security evidence could not be projected into the unified report.")
		return fallback
	}
	if projected.Programs == nil {
		projected.Programs = []services.ProgramSecurityEvidence{}
	}
	return projected
}

func applyMarketProgramEvidenceReferences(refs map[string]unifiedEvidenceReference, core holderIntelligenceCoreResult) map[string]unifiedEvidenceReference {
	if refs == nil {
		refs = map[string]unifiedEvidenceReference{}
	}

	exitRef := unifiedEvidenceReference{
		Accounts: []string{core.ExitLiquidity.Mint, core.ExitLiquidity.OutputMint},
	}
	for _, tier := range core.ExitLiquidity.Tiers {
		if !tier.Available || tier.Status != "quoted" {
			continue
		}
		if tier.QuoteContextSlot > 0 {
			exitRef.Slots = append(exitRef.Slots, int64(tier.QuoteContextSlot))
		}
		key := fmt.Sprintf("jupiter-quote:exact-in:usd-%.0f", tier.RequestedNotionalUSD)
		if tier.QuoteContextSlot > 0 {
			key += fmt.Sprintf(":slot-%d", tier.QuoteContextSlot)
		}
		exitRef.EvidenceKeys = append(exitRef.EvidenceKeys, key)
	}
	if core.ExitLiquidity.Available {
		exitRef = normalizedUnifiedEvidenceReference(exitRef)
		refs["liquidity"] = mergeUnifiedEvidenceReferences(refs["liquidity"], exitRef)
		refs["dominant-exit"] = mergeUnifiedEvidenceReferences(refs["dominant-exit"], exitRef)
	}

	program := unifiedProgramSecuritySurface(core.SourceContext)
	programRef := unifiedEvidenceReference{}
	for _, item := range program.Programs {
		programRef.Accounts = append(programRef.Accounts, item.ProgramID, item.ProgramDataAddress, item.LoaderID)
		if strings.TrimSpace(item.UpgradeAuthority) != "" {
			programRef.Wallets = append(programRef.Wallets, item.UpgradeAuthority)
		}
		if item.AccountSlot > 0 {
			programRef.Slots = append(programRef.Slots, int64(item.AccountSlot))
		}
		if item.DeploymentSlot > 0 {
			programRef.Slots = append(programRef.Slots, int64(item.DeploymentSlot))
		}
		programRef.EvidenceKeys = append(programRef.EvidenceKeys, item.EvidenceRefs...)
		if strings.TrimSpace(item.ProgramID) != "" {
			programRef.EvidenceKeys = append(programRef.EvidenceKeys, "program-security:"+strings.TrimSpace(item.Role)+":"+strings.TrimSpace(item.ProgramID))
		}
	}
	if unifiedEvidenceReferencePresent(programRef) {
		refs["program"] = mergeUnifiedEvidenceReferences(refs["program"], programRef)
	}
	return refs
}
