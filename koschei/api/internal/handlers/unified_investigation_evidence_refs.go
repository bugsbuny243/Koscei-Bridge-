package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type unifiedTransactionEvidence struct {
	Signature string     `json:"signature"`
	Slot      int64      `json:"slot,omitempty"`
	Trader    string     `json:"trader,omitempty"`
	Direction string     `json:"direction,omitempty"`
	BlockTime *time.Time `json:"block_time,omitempty"`
	Source    string     `json:"source,omitempty"`
}

type unifiedEvidenceReference struct {
	Wallets      []string `json:"wallets"`
	Accounts     []string `json:"accounts"`
	Signatures   []string `json:"signatures"`
	Slots        []int64  `json:"slots"`
	EvidenceKeys []string `json:"evidence_keys"`
}

var unifiedVerdictCardRowIDs = []string{
	"launch", "mint", "freeze", "wash", "address", "liquidity", "funding", "concentration",
	"sniper", "first-buyer", "track", "creator-sell", "dominant-exit", "liq-move", "program",
	"metadata", "claim", "mev", "distribution", "signed",
}

func (h *Handler) loadUnifiedTransactionEvidence(ctx context.Context, mint string, limit int) []unifiedTransactionEvidence {
	out := []unifiedTransactionEvidence{}
	if h == nil || strings.TrimSpace(mint) == "" {
		return out
	}
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return out
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := db.QueryContext(ctx, `
		SELECT signature,slot,trader,side,block_time,source
		FROM token_trade_events
		WHERE mint=$1
		ORDER BY COALESCE(block_time,created_at) DESC,slot DESC
		LIMIT $2`, strings.TrimSpace(mint), limit)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var item unifiedTransactionEvidence
		var slot sql.NullInt64
		var blockTime sql.NullTime
		if rows.Scan(&item.Signature, &slot, &item.Trader, &item.Direction, &blockTime, &item.Source) != nil {
			continue
		}
		item.Signature = strings.TrimSpace(item.Signature)
		item.Trader = strings.TrimSpace(item.Trader)
		item.Direction = strings.ToLower(strings.TrimSpace(item.Direction))
		item.Source = strings.TrimSpace(item.Source)
		if slot.Valid {
			item.Slot = slot.Int64
		}
		if blockTime.Valid {
			value := blockTime.Time.UTC()
			item.BlockTime = &value
		}
		if item.Signature != "" || item.Slot > 0 {
			out = append(out, item)
		}
	}
	return out
}

func buildUnifiedEvidenceReferences(core holderIntelligenceCoreResult, creator string, transactions []unifiedTransactionEvidence, behavior services.UnifiedRadarBehaviorReport, final services.UnifiedRadarVerdict) map[string]unifiedEvidenceReference {
	target := strings.TrimSpace(core.Request.Target)
	creator = strings.TrimSpace(creator)
	base := normalizedUnifiedEvidenceReference(unifiedEvidenceReference{Accounts: []string{target}})
	refs := make(map[string]unifiedEvidenceReference, len(unifiedVerdictCardRowIDs))
	for _, id := range unifiedVerdictCardRowIDs {
		refs[id] = base
	}

	topOwner, topAccounts := topRiskBearingOwnerReference(core.Intelligence)
	ownerRef := normalizedUnifiedEvidenceReference(unifiedEvidenceReference{Wallets: []string{topOwner}, Accounts: topAccounts})
	creatorRef := normalizedUnifiedEvidenceReference(unifiedEvidenceReference{Wallets: []string{creator}})
	allTradeRef := referenceFromTransactions(transactions)
	creatorSellRef := referenceFromTransactions(filterUnifiedTransactions(transactions, creator, "sell"))
	ownerExitRef := referenceFromTransactions(filterUnifiedTransactions(transactions, topOwner, "sell"))

	refs["wash"] = mergeUnifiedEvidenceReferences(refs["wash"], allTradeRef)
	refs["address"] = mergeUnifiedEvidenceReferences(refs["address"], ownerRef, creatorRef)
	fundingRecurrenceRef := unifiedEvidenceReference{}
	for _, recurrence := range core.FundingRecurrence.Sources {
		if recurrence.DistinctTargets < services.UnifiedFundingRecurrenceMinimumTargetCount || !recurrence.ReferencesComplete {
			continue
		}
		fundingRecurrenceRef.Wallets = append(fundingRecurrenceRef.Wallets, recurrence.FundingSource)
		fundingRecurrenceRef.Accounts = append(fundingRecurrenceRef.Accounts, recurrence.OtherTargets...)
	}
	refs["funding"] = mergeUnifiedEvidenceReferences(refs["funding"], creatorRef, fundingRecurrenceRef)
	refs["concentration"] = mergeUnifiedEvidenceReferences(refs["concentration"], ownerRef)
	refs["track"] = mergeUnifiedEvidenceReferences(refs["track"], creatorRef)
	refs["creator-sell"] = mergeUnifiedEvidenceReferences(refs["creator-sell"], creatorRef, creatorSellRef)
	refs["dominant-exit"] = mergeUnifiedEvidenceReferences(refs["dominant-exit"], ownerRef, ownerExitRef)
	refs["distribution"] = mergeUnifiedEvidenceReferences(refs["distribution"], allTradeRef)

	launchRef := unifiedEvidenceReference{}
	if core.LaunchForensics.LaunchSlot > 0 {
		launchRef.Slots = append(launchRef.Slots, core.LaunchForensics.LaunchSlot)
	}
	for _, profile := range core.LaunchForensics.Profiles {
		profileRef := unifiedEvidenceReference{
			Wallets:  []string{profile.OwnerWallet},
			Accounts: append([]string{}, profile.TokenAccounts...),
		}
		if profile.FirstBuySlot > 0 {
			profileRef.Slots = append(profileRef.Slots, profile.FirstBuySlot)
		}
		launchRef = mergeUnifiedEvidenceReferences(launchRef, profileRef)
		if profile.Sniper {
			refs["sniper"] = mergeUnifiedEvidenceReferences(refs["sniper"], profileRef)
		}
		if profile.CreatorLinked {
			refs["first-buyer"] = mergeUnifiedEvidenceReferences(refs["first-buyer"], profileRef, creatorRef)
		}
	}
	refs["launch"] = mergeUnifiedEvidenceReferences(refs["launch"], launchRef)
	refs["distribution"] = mergeUnifiedEvidenceReferences(refs["distribution"], launchRef)

	lpRef := normalizedUnifiedEvidenceReference(unifiedEvidenceReference{
		Accounts: []string{
			core.LPControl.PoolAddress,
			core.LPControl.LPMint,
			core.LPControl.TokenVault,
			core.LPControl.QuoteVault,
			core.LPControl.LockerAccount,
		},
		Slots:        []int64{int64(core.LPControl.ReadSlot)},
		EvidenceKeys: append([]string{}, core.LPControl.EvidenceKeys...),
	})
	refs["liquidity"] = mergeUnifiedEvidenceReferences(refs["liquidity"], lpRef)
	refs["liq-move"] = mergeUnifiedEvidenceReferences(refs["liq-move"], lpRef)
	if core.JupiterContext.QuoteContextSlot > 0 {
		refs["concentration"] = mergeUnifiedEvidenceReferences(refs["concentration"], unifiedEvidenceReference{Slots: []int64{int64(core.JupiterContext.QuoteContextSlot)}})
	}

	for _, signal := range behavior.Signals {
		signalRef := normalizedUnifiedEvidenceReference(unifiedEvidenceReference{
			Signatures:   append([]string{}, signal.Signatures...),
			EvidenceKeys: append([]string{}, signal.EvidenceKeys...),
		})
		switch signal.RuleID {
		case services.UnifiedRuleCreatorSellAcceleration:
			refs["creator-sell"] = mergeUnifiedEvidenceReferences(refs["creator-sell"], signalRef)
		case services.UnifiedRuleDominantHolderFirstExit:
			refs["dominant-exit"] = mergeUnifiedEvidenceReferences(refs["dominant-exit"], signalRef)
		case services.UnifiedRuleOwnerConcentration:
			refs["concentration"] = mergeUnifiedEvidenceReferences(refs["concentration"], signalRef)
		}
	}

	for _, arm := range core.Arms {
		armRef := evidenceReferenceFromArm(arm)
		moduleID := strings.ToLower(strings.TrimSpace(arm.ModuleID + " " + arm.Module))
		for _, id := range evidenceRowsForModule(moduleID) {
			refs[id] = mergeUnifiedEvidenceReferences(refs[id], armRef)
		}
	}

	signedRef := unifiedEvidenceReference{}
	if strings.TrimSpace(final.Signature) != "" {
		signedRef.Signatures = []string{strings.TrimSpace(final.Signature)}
		signedRef.EvidenceKeys = []string{"verdict-signature:" + strings.TrimSpace(final.Signature)}
	}
	refs["signed"] = mergeUnifiedEvidenceReferences(refs["signed"], signedRef)
	return refs
}

func topRiskBearingOwnerReference(holder services.HolderIntelligence) (string, []string) {
	for _, row := range holder.Rows {
		if row.OwnerResolved && row.RiskBearing && !row.ExcludedFromHolderRisk && strings.TrimSpace(row.OwnerWallet) != "" {
			return strings.TrimSpace(row.OwnerWallet), append([]string{}, row.TokenAccounts...)
		}
	}
	return "", []string{}
}

func filterUnifiedTransactions(values []unifiedTransactionEvidence, wallet, direction string) []unifiedTransactionEvidence {
	wallet = strings.TrimSpace(wallet)
	direction = strings.ToLower(strings.TrimSpace(direction))
	out := []unifiedTransactionEvidence{}
	for _, value := range values {
		if wallet != "" && strings.TrimSpace(value.Trader) != wallet {
			continue
		}
		if direction != "" && strings.ToLower(strings.TrimSpace(value.Direction)) != direction {
			continue
		}
		out = append(out, value)
	}
	return out
}

func referenceFromTransactions(values []unifiedTransactionEvidence) unifiedEvidenceReference {
	out := unifiedEvidenceReference{}
	for _, value := range values {
		out.Wallets = append(out.Wallets, value.Trader)
		out.Signatures = append(out.Signatures, value.Signature)
		out.Slots = append(out.Slots, value.Slot)
	}
	return normalizedUnifiedEvidenceReference(out)
}

func evidenceReferenceFromArm(arm services.SecurityRadarVerdict) unifiedEvidenceReference {
	out := unifiedEvidenceReference{Accounts: []string{arm.Target}, Signatures: []string{arm.Signature}}
	for _, key := range []string{"signature", "transaction_signature", "source_signature", "creator_creation_signatures", "exit_event_signatures"} {
		out.Signatures = append(out.Signatures, signalStringValues(arm.Signals[key])...)
	}
	for _, key := range []string{"evidence_key", "evidence_keys"} {
		out.EvidenceKeys = append(out.EvidenceKeys, signalStringValues(arm.Signals[key])...)
	}
	for _, key := range []string{"slot", "read_slot", "context_slot", "launch_slot"} {
		if slot := signalInt64(arm.Signals[key]); slot > 0 {
			out.Slots = append(out.Slots, slot)
		}
	}
	for _, key := range []string{"creator_creation_slots", "exit_event_slots"} {
		for _, slot := range signalInt64Values(arm.Signals[key]) {
			out.Slots = append(out.Slots, slot)
		}
	}
	for _, key := range []string{"owner_wallet", "creator_wallet", "wallet", "trader", "exit_event_actor_wallet"} {
		out.Wallets = append(out.Wallets, signalStringValues(arm.Signals[key])...)
	}
	for _, key := range []string{"account", "account_address", "pool_address", "lp_mint", "token_vault", "quote_vault", "creator_other_mints", "exit_event_other_mints"} {
		out.Accounts = append(out.Accounts, signalStringValues(arm.Signals[key])...)
	}
	return normalizedUnifiedEvidenceReference(out)
}

func evidenceRowsForModule(moduleID string) []string {
	mapping := []struct {
		needles []string
		rows    []string
	}{
		{[]string{"token_authority", "authority_scanner"}, []string{"mint", "freeze", "program"}},
		{[]string{"trade_ledger", "wash"}, []string{"wash"}},
		{[]string{"actor_dossier", "address_behavior"}, []string{"address", "track"}},
		{[]string{"liquidity_movement", "raydium_pool"}, []string{"liquidity", "liq-move"}},
		{[]string{"funding"}, []string{"funding"}},
		{[]string{"holder_concentration"}, []string{"concentration"}},
		{[]string{"sniper"}, []string{"sniper"}},
		{[]string{"pump_sybil"}, []string{"first-buyer"}},
		{[]string{"repeat_actor"}, []string{"track"}},
		{[]string{"creator_sell"}, []string{"creator-sell"}},
		{[]string{"dominant_holder"}, []string{"dominant-exit"}},
		{[]string{"program_relation"}, []string{"program"}},
		{[]string{"metadata"}, []string{"metadata"}},
		{[]string{"claim"}, []string{"claim"}},
		{[]string{"mev"}, []string{"mev"}},
		{[]string{"launch_distribution", "launch_forensics"}, []string{"launch", "distribution"}},
	}
	rows := []string{}
	for _, item := range mapping {
		for _, needle := range item.needles {
			if strings.Contains(moduleID, needle) {
				rows = append(rows, item.rows...)
				break
			}
		}
	}
	return uniqueStringsSorted(rows)
}

func mergeUnifiedEvidenceReferences(values ...unifiedEvidenceReference) unifiedEvidenceReference {
	out := unifiedEvidenceReference{}
	for _, value := range values {
		out.Wallets = append(out.Wallets, value.Wallets...)
		out.Accounts = append(out.Accounts, value.Accounts...)
		out.Signatures = append(out.Signatures, value.Signatures...)
		out.Slots = append(out.Slots, value.Slots...)
		out.EvidenceKeys = append(out.EvidenceKeys, value.EvidenceKeys...)
	}
	return normalizedUnifiedEvidenceReference(out)
}

func normalizedUnifiedEvidenceReference(value unifiedEvidenceReference) unifiedEvidenceReference {
	value.Wallets = uniqueStringsSorted(value.Wallets)
	value.Accounts = uniqueStringsSorted(value.Accounts)
	value.Signatures = uniqueStringsSorted(value.Signatures)
	value.EvidenceKeys = uniqueStringsSorted(value.EvidenceKeys)
	value.Slots = uniquePositiveInt64s(value.Slots)
	return value
}

func unifiedEvidenceReferencePresent(value unifiedEvidenceReference) bool {
	return len(value.Wallets)+len(value.Accounts)+len(value.Signatures)+len(value.Slots)+len(value.EvidenceKeys) > 0
}

func uniqueStringsSorted(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uniquePositiveInt64s(values []int64) []int64 {
	seen := map[int64]bool{}
	out := []int64{}
	for _, value := range values {
		if value <= 0 || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func signalStringValues(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, fmt.Sprint(item))
		}
		return out
	default:
		return []string{}
	}
}

func signalInt64Values(value any) []int64 {
	out := []int64{}
	switch typed := value.(type) {
	case []int64:
		return append(out, typed...)
	case []any:
		for _, item := range typed {
			if slot := signalInt64(item); slot > 0 {
				out = append(out, slot)
			}
		}
	}
	return out
}

func signalInt64(value any) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int64:
		return typed
	case uint64:
		if typed <= uint64(^uint64(0)>>1) {
			return int64(typed)
		}
	case float64:
		return int64(typed)
	case string:
		parsed, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return parsed
	}
	return 0
}
