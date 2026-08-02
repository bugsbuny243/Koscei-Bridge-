package services

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	holderClusterWalletLimit            = 20
	holderClusterSignatureLimit         = 20 // legacy helper default; tiered scans use env-backed limits
	holderClusterParsedTransactionLimit = 3  // legacy helper default; tiered scans use env-backed limits
)

// HolderClusterWallet records bounded, evidence-scoped observations for one
// risk-bearing holder owner. An observation is never treated as real-world
// identity proof or sole proof of common control.
type HolderClusterWallet struct {
	Rank                  int                            `json:"rank"`
	Wallet                string                         `json:"wallet"`
	HolderPercentage      float64                        `json:"holder_percentage"`
	Status                string                         `json:"status"`
	Tier                  string                         `json:"tier"`
	Collector             string                         `json:"collector,omitempty"`
	SignaturesFetched     int                            `json:"signatures_fetched"`
	TxsParsed             int                            `json:"txs_parsed"`
	WindowExhausted       bool                           `json:"window_exhausted"`
	BudgetDegraded        bool                           `json:"budget_degraded,omitempty"`
	SignaturesObserved    int                            `json:"signatures_observed"`
	ParsedTransactions    int                            `json:"parsed_transactions"`
	HistoryExhausted      bool                           `json:"history_exhausted"`
	OldestObservedAt      string                         `json:"oldest_observed_at,omitempty"`
	NewestObservedAt      string                         `json:"newest_observed_at,omitempty"`
	OldestObservedSlot    int64                          `json:"oldest_observed_slot,omitempty"`
	FundingSource         string                         `json:"funding_source,omitempty"`
	FundingAmountSOL      float64                        `json:"funding_amount_sol,omitempty"`
	FundingObservedAt     string                         `json:"funding_observed_at,omitempty"`
	AcquisitionSlot       int64                          `json:"acquisition_slot,omitempty"`
	AcquisitionObservedAt string                         `json:"acquisition_observed_at,omitempty"`
	FreshNearLaunch       bool                           `json:"fresh_near_launch"`
	FlowObservations      []HolderClusterFlowObservation `json:"flow_observations"`
	Evidence              []string                       `json:"evidence"`
}

// HolderClusterGroup describes a repeated relation shared by at least two
// holder wallets. The key can be a funding wallet or a normalized SOL amount.
type HolderClusterGroup struct {
	Key              string   `json:"key"`
	Wallets          []string `json:"wallets"`
	MemberCount      int      `json:"member_count"`
	HolderPercentage float64  `json:"holder_percentage"`
	Evidence         []string `json:"evidence"`
}

// HolderClusterAnalysis combines fresh-wallet, shared-funding and synchronized
// acquisition evidence. Low risk is issued only when at least three holder
// wallets were actually observed; unavailable evidence never becomes LOW.
type HolderClusterAnalysis struct {
	Available                 bool                      `json:"available"`
	Status                    string                    `json:"status"`
	RiskIndex                 int                       `json:"risk_index,omitempty"`
	RiskLevel                 string                    `json:"risk_level,omitempty"`
	Confidence                string                    `json:"confidence"`
	Verdict                   string                    `json:"verdict"`
	WalletsRequested          int                       `json:"wallets_requested"`
	WalletsAnalyzed           int                       `json:"wallets_analyzed"`
	DeepOwnersScanned         int                       `json:"deep_owners_scanned"`
	ShallowOwnersScanned      int                       `json:"shallow_owners_scanned"`
	DeepSignatureLimit        int                       `json:"deep_signature_limit"`
	DeepTransactionLimit      int                       `json:"deep_transaction_limit"`
	ShallowSignatureLimit     int                       `json:"shallow_signature_limit"`
	ShallowTransactionLimit   int                       `json:"shallow_transaction_limit"`
	RPCBudget                 int                       `json:"rpc_budget"`
	RPCCallsUsed              int                       `json:"rpc_calls_used"`
	BudgetDegradedOwners      int                       `json:"budget_degraded_owners"`
	FreshWalletCount          int                       `json:"fresh_wallet_count"`
	SharedFundingGroupCount   int                       `json:"shared_funding_group_count"`
	LargestSharedFundingGroup int                       `json:"largest_shared_funding_group"`
	SameAmountGroupCount      int                       `json:"same_amount_group_count"`
	LargestSameAmountGroup    int                       `json:"largest_same_amount_group"`
	SynchronizedWalletCount   int                       `json:"synchronized_wallet_count"`
	SynchronizationSlotSpread int64                     `json:"synchronization_slot_spread,omitempty"`
	LinkedHolderPercentage    float64                   `json:"linked_holder_percentage"`
	LaunchEstimateAt          string                    `json:"launch_estimate_at,omitempty"`
	LaunchEstimateSlot        int64                     `json:"launch_estimate_slot,omitempty"`
	Wallets                   []HolderClusterWallet     `json:"wallets"`
	SharedFundingGroups       []HolderClusterGroup      `json:"shared_funding_groups"`
	SameAmountGroups          []HolderClusterGroup      `json:"same_amount_groups"`
	SynchronizedWallets       []string                  `json:"synchronized_wallets"`
	Flow                      HolderClusterFlowAnalysis `json:"flow"`
	Findings                  []string                  `json:"findings"`
	Limitations               []string                  `json:"limitations"`
}

func AnalyzeSolanaHolderCluster(ctx context.Context, rpcURL, mint string, roles HolderRoleAnalysis, launchBlockTime, launchSlot int64) HolderClusterAnalysis {
	out := HolderClusterAnalysis{
		Status: "insufficient_evidence", Confidence: "none", Verdict: "INSUFFICIENT EVIDENCE",
		Wallets: []HolderClusterWallet{}, SharedFundingGroups: []HolderClusterGroup{},
		SameAmountGroups: []HolderClusterGroup{}, SynchronizedWallets: []string{},
		Findings: []string{}, Limitations: []string{}, LaunchEstimateSlot: launchSlot,
	}
	if launchBlockTime > 0 {
		out.LaunchEstimateAt = time.Unix(launchBlockTime, 0).UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(rpcURL) == "" || strings.TrimSpace(mint) == "" || !roles.Available {
		out.Limitations = append(out.Limitations, "Live Solana RPC, token mint and resolved holder-owner evidence are required.")
		return out
	}

	cfg := loadHolderScanTierConfig()
	candidates := holderClusterRiskOwnerCandidates(roles.Accounts, holderClusterWalletLimit)
	plans := holderClusterAssignScanTiers(candidates, cfg)
	budget := newHolderScanRPCBudget(cfg.RPCBudget)
	out.DeepSignatureLimit = cfg.DeepSignatureLimit
	out.DeepTransactionLimit = cfg.DeepTransactionLimit
	out.ShallowSignatureLimit = cfg.ShallowSignatureLimit
	out.ShallowTransactionLimit = cfg.ShallowTransactionLimit
	out.RPCBudget = cfg.RPCBudget
	out.WalletsRequested = len(candidates)
	candidateWallets := map[string]bool{}
	for _, candidate := range candidates {
		candidateWallets[candidate.OwnerWallet] = true
	}
	if len(candidates) < 3 {
		out.Limitations = append(out.Limitations, "At least three resolved risk-bearing holder wallets are required for cluster analysis.")
		return out
	}

	for i, account := range candidates {
		if ctx.Err() != nil {
			out.Limitations = append(out.Limitations, "Cluster analysis stopped at the request deadline; partial observations are preserved.")
			break
		}
		plan := plans[i]
		row, enhancedOK := analyzeHolderClusterWalletEnhanced(ctx, rpcURL, mint, account, launchBlockTime, candidateWallets, plan, budget)
		collector := "helius_enhanced"
		if !enhancedOK {
			row = analyzeHolderClusterWalletTiered(ctx, rpcURL, mint, account, launchBlockTime, candidateWallets, plan, budget)
			collector = "solana_rpc"
		}
		// Tier describes investigation depth. Collector describes the transport.
		// Never overwrite deep/shallow with a provider name.
		row.Tier = plan.Tier
		row.Collector = collector
		if plan.Tier == "deep" {
			out.DeepOwnersScanned++
		} else {
			out.ShallowOwnersScanned++
		}
		if row.BudgetDegraded {
			out.BudgetDegradedOwners++
		}
		out.Wallets = append(out.Wallets, row)
	}
	out.RPCCallsUsed = budget.Used()
	return summarizeHolderCluster(out)
}

func analyzeHolderClusterWallet(ctx context.Context, rpcURL, mint string, account HolderRoleAccount, launchBlockTime int64, holderWallets map[string]bool) HolderClusterWallet {
	percentage := account.CirculatingPercentage
	if percentage <= 0 {
		percentage = account.RawPercentage
	}
	row := HolderClusterWallet{
		Rank: account.Rank, Wallet: account.OwnerWallet, HolderPercentage: holderClusterRound(percentage, 4),
		Status: "signature_history_unavailable", FlowObservations: []HolderClusterFlowObservation{}, Evidence: []string{},
	}
	signatures, err := SolanaGetSignaturesForAddress(ctx, rpcURL, account.OwnerWallet, holderClusterSignatureLimit)
	if err != nil {
		row.Evidence = append(row.Evidence, "Holder signature history could not be fetched: "+compactClusterError(err))
		return row
	}
	row.SignaturesObserved = len(signatures)
	row.HistoryExhausted = len(signatures) < holderClusterSignatureLimit
	if len(signatures) == 0 {
		row.Status = "no_observed_signatures"
		row.Evidence = append(row.Evidence, "No signatures were returned in the bounded holder history query.")
		return row
	}

	var oldestTime, newestTime, oldestSlot int64
	for _, signature := range signatures {
		if signature.BlockTime == nil || *signature.BlockTime <= 0 {
			continue
		}
		if newestTime == 0 || *signature.BlockTime > newestTime {
			newestTime = *signature.BlockTime
		}
		if oldestTime == 0 || *signature.BlockTime < oldestTime {
			oldestTime = *signature.BlockTime
			oldestSlot = signature.Slot
		}
	}
	row.OldestObservedSlot = oldestSlot
	row.OldestObservedAt = holderClusterUnixTime(oldestTime)
	row.NewestObservedAt = holderClusterUnixTime(newestTime)
	if row.HistoryExhausted && launchBlockTime > 0 && oldestTime > 0 {
		delta := oldestTime - launchBlockTime
		row.FreshNearLaunch = delta >= -86400 && delta <= 86400
	}

	candidateIndexes := holderClusterTransactionIndexes(signatures, launchBlockTime)
	for _, index := range candidateIndexes {
		if index < 0 || index >= len(signatures) || signatures[index].Err != nil || strings.TrimSpace(signatures[index].Signature) == "" {
			continue
		}
		tx, txErr := SolanaGetTransactionJSONParsed(ctx, rpcURL, signatures[index].Signature)
		if txErr != nil {
			continue
		}
		row.ParsedTransactions++
		txMap := map[string]any(tx)
		blockTime := holderClusterInt64(txMap["blockTime"])
		slot := holderClusterInt64(txMap["slot"])
		row.FlowObservations = append(row.FlowObservations, observeHolderClusterWalletFlow(txMap, signatures[index].Signature, mint, account.OwnerWallet, holderWallets)...)
		if row.FundingSource == "" {
			if source, amount := holderClusterFundingSource(txMap, account.OwnerWallet); source != "" && amount > 0 {
				row.FundingSource = source
				row.FundingAmountSOL = holderClusterRound(amount, 9)
				row.FundingObservedAt = holderClusterUnixTime(blockTime)
			}
		}
		if delta := holderClusterOwnerTokenDelta(txMap, mint, account.OwnerWallet); delta > 0.000000001 {
			if row.AcquisitionSlot == 0 || (slot > 0 && slot < row.AcquisitionSlot) {
				row.AcquisitionSlot = slot
				row.AcquisitionObservedAt = holderClusterUnixTime(blockTime)
			}
		}
	}
	if row.ParsedTransactions > 0 {
		row.Status = "verified_bounded_observation"
	} else {
		row.Status = "signature_only_observation"
	}
	row.Evidence = append(row.Evidence, fmt.Sprintf("Observed %d signatures and parsed %d transactions; history exhausted within query window: %t.", row.SignaturesObserved, row.ParsedTransactions, row.HistoryExhausted))
	if row.FreshNearLaunch {
		row.Evidence = append(row.Evidence, "Oldest observed wallet activity falls within 24 hours of the bounded token launch estimate.")
	}
	if row.FundingSource != "" {
		row.Evidence = append(row.Evidence, fmt.Sprintf("First bounded funding relation: %s supplied approximately %.9f SOL.", row.FundingSource, row.FundingAmountSOL))
	}
	if row.AcquisitionSlot > 0 {
		row.Evidence = append(row.Evidence, fmt.Sprintf("Positive target-token acquisition was observed at slot %d.", row.AcquisitionSlot))
	}
	return row
}

func summarizeHolderCluster(out HolderClusterAnalysis) HolderClusterAnalysis {
	out.Flow = summarizeHolderClusterFlow(out.Wallets)
	funding := map[string][]HolderClusterWallet{}
	amounts := map[string][]HolderClusterWallet{}
	acquisitions := []HolderClusterWallet{}
	for _, wallet := range out.Wallets {
		if wallet.Status == "verified_bounded_observation" && wallet.ParsedTransactions > 0 {
			out.WalletsAnalyzed++
		}
		if wallet.FreshNearLaunch {
			out.FreshWalletCount++
		}
		if wallet.FundingSource != "" {
			funding[wallet.FundingSource] = append(funding[wallet.FundingSource], wallet)
		}
		if wallet.FundingAmountSOL > 0 {
			key := fmt.Sprintf("%.6f SOL", wallet.FundingAmountSOL)
			amounts[key] = append(amounts[key], wallet)
		}
		if wallet.AcquisitionSlot > 0 {
			acquisitions = append(acquisitions, wallet)
		}
	}
	if out.WalletsAnalyzed < 3 {
		out.Limitations = append(out.Limitations, "Fewer than three holder wallets produced parsed transaction evidence; no LOW verdict is issued.")
		return out
	}

	for source, wallets := range funding {
		if len(wallets) < 2 {
			continue
		}
		group := holderClusterGroup(source, wallets, fmt.Sprintf("%d holder wallets share the same observed funding source.", len(wallets)))
		out.SharedFundingGroups = append(out.SharedFundingGroups, group)
		if group.MemberCount > out.LargestSharedFundingGroup {
			out.LargestSharedFundingGroup = group.MemberCount
		}
	}
	for amount, wallets := range amounts {
		if len(wallets) < 2 {
			continue
		}
		group := holderClusterGroup(amount, wallets, fmt.Sprintf("%d holder wallets received the same rounded SOL funding amount.", len(wallets)))
		out.SameAmountGroups = append(out.SameAmountGroups, group)
		if group.MemberCount > out.LargestSameAmountGroup {
			out.LargestSameAmountGroup = group.MemberCount
		}
	}
	sort.SliceStable(out.SharedFundingGroups, func(i, j int) bool {
		return out.SharedFundingGroups[i].MemberCount > out.SharedFundingGroups[j].MemberCount
	})
	sort.SliceStable(out.SameAmountGroups, func(i, j int) bool { return out.SameAmountGroups[i].MemberCount > out.SameAmountGroups[j].MemberCount })
	out.SharedFundingGroupCount = len(out.SharedFundingGroups)
	out.SameAmountGroupCount = len(out.SameAmountGroups)

	syncWallets, spread := holderClusterSynchronizedWallets(acquisitions, 3)
	out.SynchronizedWallets = syncWallets
	out.SynchronizedWalletCount = len(syncWallets)
	out.SynchronizationSlotSpread = spread

	suspicious := map[string]bool{}
	if len(out.SharedFundingGroups) > 0 {
		for _, wallet := range out.SharedFundingGroups[0].Wallets {
			suspicious[wallet] = true
		}
	}
	if len(out.SameAmountGroups) > 0 {
		for _, wallet := range out.SameAmountGroups[0].Wallets {
			suspicious[wallet] = true
		}
	}
	for _, wallet := range out.SynchronizedWallets {
		suspicious[wallet] = true
	}
	for _, wallet := range out.Flow.LinkedWallets {
		suspicious[wallet] = true
	}
	for _, wallet := range out.Wallets {
		if suspicious[wallet.Wallet] {
			out.LinkedHolderPercentage += wallet.HolderPercentage
		}
	}
	out.LinkedHolderPercentage = holderClusterRound(out.LinkedHolderPercentage, 4)

	score := 5
	switch {
	case out.FreshWalletCount >= 5:
		score += 25
	case out.FreshWalletCount >= 3:
		score += 15
	}
	switch {
	case out.LargestSharedFundingGroup >= 5:
		score += 45
	case out.LargestSharedFundingGroup >= 3:
		score += 30
	case out.LargestSharedFundingGroup >= 2:
		score += 12
	}
	if out.LargestSameAmountGroup >= 3 {
		score += 15
	} else if out.LargestSameAmountGroup >= 2 {
		score += 6
	}
	switch {
	case out.SynchronizedWalletCount >= 5:
		score += 35
	case out.SynchronizedWalletCount >= 3:
		score += 25
	case out.SynchronizedWalletCount >= 2:
		score += 8
	}
	if out.LargestSharedFundingGroup >= 3 && out.SynchronizedWalletCount >= 3 {
		score += 15
	}
	score += out.Flow.RiskContribution
	if out.Flow.LargestCommonExitGroup >= 3 && out.LargestSharedFundingGroup >= 2 {
		score += 12
	}
	if score > 100 {
		score = 100
	}
	out.Available = true
	out.Status = "verified_bounded_holder_cluster_observation"
	out.RiskIndex = score
	out.RiskLevel = riskLevelFromIndex(score)
	switch {
	case out.LargestSharedFundingGroup >= 3 && out.SynchronizedWalletCount >= 3:
		out.Confidence = "high"
	case out.Flow.Confidence == "high" && (out.LargestSharedFundingGroup >= 2 || out.SynchronizedWalletCount >= 2):
		out.Confidence = "high"
	case out.LargestSharedFundingGroup >= 2 || out.SynchronizedWalletCount >= 3 || out.FreshWalletCount >= 3 || out.Flow.Confidence == "medium" || out.Flow.Confidence == "high":
		out.Confidence = "medium"
	default:
		out.Confidence = "low"
	}
	switch {
	case score >= 70:
		out.Verdict = "HIGH SYBIL / COORDINATED HOLDER RISK"
	case score >= 45:
		out.Verdict = "POSSIBLE COORDINATED HOLDER CLUSTER"
	default:
		out.Verdict = "NO STRONG COORDINATION FOUND IN THE BOUNDED WINDOW"
	}
	out.Findings = holderClusterFindings(out)
	out.Limitations = append(out.Limitations, out.Flow.Limitations...)
	out.Limitations = append(out.Limitations,
		fmt.Sprintf("Tiered holder history: first %d risk-bearing owners use up to %d signatures / %d parsed transactions; remaining owners use up to %d / %d. Provider budget units used: %d of %d.", out.DeepOwnersScanned, out.DeepSignatureLimit, out.DeepTransactionLimit, out.ShallowSignatureLimit, out.ShallowTransactionLimit, out.RPCCallsUsed, out.RPCBudget),
		"A shallow window with no observed activity contributes zero safety weight; it is not evidence that activity does not exist.",
		"A shared funding source can be an exchange or service wallet; common control is not claimed without combined timing and graph evidence.",
		"Wash trading requires circular swap/transfer evidence and is not claimed from holder freshness alone.",
	)
	return out
}

func holderClusterFindings(out HolderClusterAnalysis) []string {
	findings := []string{
		fmt.Sprintf("Verified bounded observations were produced for %d of %d requested holder wallets.", out.WalletsAnalyzed, out.WalletsRequested),
		fmt.Sprintf("First %d owners were investigated with the deep window (%d history entries / %d parsed transactions); the remaining %d owners used the standard window (%d / %d).", out.DeepOwnersScanned, out.DeepSignatureLimit, out.DeepTransactionLimit, out.ShallowOwnersScanned, out.ShallowSignatureLimit, out.ShallowTransactionLimit),
	}
	if out.FreshWalletCount > 0 {
		findings = append(findings, fmt.Sprintf("%d holder wallets have exhausted bounded histories whose oldest activity falls within 24 hours of the launch estimate.", out.FreshWalletCount))
	}
	if len(out.SharedFundingGroups) > 0 {
		group := out.SharedFundingGroups[0]
		findings = append(findings, fmt.Sprintf("Largest shared-funding group: source %s, %d wallets, %.4f%% linked supply; members: %s.", group.Key, group.MemberCount, group.HolderPercentage, strings.Join(group.Wallets, ", ")))
	}
	if len(out.SameAmountGroups) > 0 {
		group := out.SameAmountGroups[0]
		findings = append(findings, fmt.Sprintf("Largest same-funding-amount group: %s, %d wallets, %.4f%% linked supply; members: %s. Equal amount is not proof of a shared source.", group.Key, group.MemberCount, group.HolderPercentage, strings.Join(group.Wallets, ", ")))
	}
	if out.SynchronizedWalletCount >= 2 {
		findings = append(findings, fmt.Sprintf("%d holder wallets acquired the token within a %d-slot window.", out.SynchronizedWalletCount, out.SynchronizationSlotSpread))
	}
	if out.LinkedHolderPercentage > 0 {
		findings = append(findings, fmt.Sprintf("Wallets in the strongest funding/timing relations represent approximately %.4f%% of role-adjusted holder supply.", out.LinkedHolderPercentage))
	}
	findings = append(findings, out.Flow.Findings...)
	if len(findings) == 1 {
		findings = append(findings, "No repeated shared-funding, synchronized-acquisition, common-exit or internal-transfer pattern was verified in the bounded observation window.")
	}
	return findings
}

func holderClusterGroup(key string, wallets []HolderClusterWallet, evidence string) HolderClusterGroup {
	group := HolderClusterGroup{Key: key, Wallets: []string{}, MemberCount: len(wallets), Evidence: []string{evidence}}
	for _, wallet := range wallets {
		group.Wallets = append(group.Wallets, wallet.Wallet)
		group.HolderPercentage += wallet.HolderPercentage
	}
	group.HolderPercentage = holderClusterRound(group.HolderPercentage, 4)
	return group
}

func holderClusterSynchronizedWallets(wallets []HolderClusterWallet, maxSpread int64) ([]string, int64) {
	if len(wallets) < 2 {
		return []string{}, 0
	}
	sort.SliceStable(wallets, func(i, j int) bool { return wallets[i].AcquisitionSlot < wallets[j].AcquisitionSlot })
	bestStart, bestEnd := 0, 0
	for start := 0; start < len(wallets); start++ {
		end := start
		for end+1 < len(wallets) && wallets[end+1].AcquisitionSlot-wallets[start].AcquisitionSlot <= maxSpread {
			end++
		}
		if end-start > bestEnd-bestStart {
			bestStart, bestEnd = start, end
		}
	}
	if bestEnd-bestStart+1 < 2 {
		return []string{}, 0
	}
	out := make([]string, 0, bestEnd-bestStart+1)
	for _, wallet := range wallets[bestStart : bestEnd+1] {
		out = append(out, wallet.Wallet)
	}
	return out, wallets[bestEnd].AcquisitionSlot - wallets[bestStart].AcquisitionSlot
}

func holderClusterTransactionIndexes(signatures []SolanaSignatureInfo, launchBlockTime int64) []int {
	if len(signatures) == 0 {
		return nil
	}
	indexes := []int{}
	seen := map[int]bool{}
	appendIndex := func(index int) {
		if index < 0 || index >= len(signatures) || seen[index] || signatures[index].Err != nil || strings.TrimSpace(signatures[index].Signature) == "" {
			return
		}
		seen[index] = true
		indexes = append(indexes, index)
	}

	// Newest successful transaction captures recent exit/transfer behavior.
	for i := 0; i < len(signatures); i++ {
		if signatures[i].Err == nil && strings.TrimSpace(signatures[i].Signature) != "" {
			appendIndex(i)
			break
		}
	}
	// Oldest bounded transaction captures initial funding/age evidence.
	for i := len(signatures) - 1; i >= 0; i-- {
		if signatures[i].Err == nil && strings.TrimSpace(signatures[i].Signature) != "" {
			appendIndex(i)
			break
		}
	}
	// Closest transaction to the bounded launch estimate captures acquisition timing.
	if launchBlockTime > 0 {
		closest, best := -1, int64(math.MaxInt64)
		for i, signature := range signatures {
			if signature.Err != nil || signature.BlockTime == nil || *signature.BlockTime <= 0 || strings.TrimSpace(signature.Signature) == "" {
				continue
			}
			delta := *signature.BlockTime - launchBlockTime
			if delta < 0 {
				delta = -delta
			}
			if delta < best {
				best, closest = delta, i
			}
		}
		appendIndex(closest)
	}
	if len(indexes) > holderClusterParsedTransactionLimit {
		indexes = indexes[:holderClusterParsedTransactionLimit]
	}
	return indexes
}

func holderClusterFundingSource(tx map[string]any, wallet string) (string, float64) {
	message := holderClusterMap(holderClusterMap(tx["transaction"])["message"])
	meta := holderClusterMap(tx["meta"])
	keys := holderClusterAccountKeys(message["accountKeys"])
	pre := holderClusterNumberSlice(meta["preBalances"])
	post := holderClusterNumberSlice(meta["postBalances"])
	limit := len(keys)
	if len(pre) < limit {
		limit = len(pre)
	}
	if len(post) < limit {
		limit = len(post)
	}
	walletIndex := -1
	for i := 0; i < limit; i++ {
		if strings.EqualFold(keys[i], wallet) {
			walletIndex = i
			break
		}
	}
	if walletIndex < 0 || post[walletIndex]-pre[walletIndex] <= 10000 {
		return "", 0
	}
	bestIndex, bestOutflow := -1, int64(0)
	for i := 0; i < limit; i++ {
		if i == walletIndex || keys[i] == "" {
			continue
		}
		delta := post[i] - pre[i]
		if delta < bestOutflow {
			bestOutflow, bestIndex = delta, i
		}
	}
	if bestIndex < 0 {
		return "", 0
	}
	return keys[bestIndex], float64(-bestOutflow) / 1e9
}

func holderClusterOwnerTokenDelta(tx map[string]any, mint, wallet string) float64 {
	meta := holderClusterMap(tx["meta"])
	pre := holderClusterTokenBalances(meta["preTokenBalances"], mint, wallet)
	post := holderClusterTokenBalances(meta["postTokenBalances"], mint, wallet)
	return post - pre
}

func holderClusterTokenBalances(raw any, mint, wallet string) float64 {
	total := 0.0
	for _, item := range holderClusterSlice(raw) {
		row := holderClusterMap(item)
		if !strings.EqualFold(holderClusterString(row["mint"]), mint) || !strings.EqualFold(holderClusterString(row["owner"]), wallet) {
			continue
		}
		amount := holderClusterMap(row["uiTokenAmount"])
		if text := holderClusterString(amount["uiAmountString"]); text != "" {
			parsed, _ := strconv.ParseFloat(text, 64)
			total += parsed
			continue
		}
		total += holderClusterFloat(amount["uiAmount"])
	}
	return total
}

func holderClusterAccountKeys(raw any) []string {
	out := []string{}
	for _, item := range holderClusterSlice(raw) {
		switch value := item.(type) {
		case string:
			out = append(out, strings.TrimSpace(value))
		case map[string]any:
			out = append(out, holderClusterString(value["pubkey"]))
		default:
			out = append(out, holderClusterString(item))
		}
	}
	return out
}

func holderClusterNumberSlice(raw any) []int64 {
	items := holderClusterSlice(raw)
	out := make([]int64, 0, len(items))
	for _, item := range items {
		out = append(out, holderClusterInt64(item))
	}
	return out
}

func holderClusterMap(raw any) map[string]any {
	value, _ := raw.(map[string]any)
	if value == nil {
		return map[string]any{}
	}
	return value
}
func holderClusterSlice(raw any) []any { value, _ := raw.([]any); return value }
func holderClusterString(raw any) string {
	value := strings.TrimSpace(fmt.Sprint(raw))
	if value == "<nil>" {
		return ""
	}
	return value
}
func holderClusterFloat(raw any) float64 {
	switch value := raw.(type) {
	case float64:
		return value
	case int:
		return float64(value)
	case int64:
		return float64(value)
	}
	parsed, _ := strconv.ParseFloat(holderClusterString(raw), 64)
	return parsed
}
func holderClusterInt64(raw any) int64 {
	switch value := raw.(type) {
	case int64:
		return value
	case int:
		return int64(value)
	case float64:
		return int64(value)
	}
	parsed, _ := strconv.ParseInt(holderClusterString(raw), 10, 64)
	return parsed
}
func holderClusterRound(value float64, digits int) float64 {
	factor := math.Pow10(digits)
	return math.Round(value*factor) / factor
}
func holderClusterUnixTime(value int64) string {
	if value <= 0 {
		return ""
	}
	return time.Unix(value, 0).UTC().Format(time.RFC3339)
}
func compactClusterError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(err.Error())
	if len(value) > 180 {
		value = value[:180]
	}
	return value
}
