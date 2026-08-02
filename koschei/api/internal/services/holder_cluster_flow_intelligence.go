package services

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

const holderClusterFlowEpsilon = 0.000000001

// HolderClusterFlowObservation records one evidence-scoped target-token
// transfer. It never claims real-world identity, ownership or wash trading on
// its own. Entity and risk fields are populated only from positively-resolved
// third-party identity metadata.
type HolderClusterFlowObservation struct {
	SourceWallet            string   `json:"source_wallet"`
	Destination             string   `json:"destination"`
	Mint                    string   `json:"mint,omitempty"`
	SourceTokenAccount      string   `json:"source_token_account,omitempty"`
	DestinationTokenAccount string   `json:"destination_token_account,omitempty"`
	TokenStandard           string   `json:"token_standard,omitempty"`
	Decimals                *int     `json:"decimals,omitempty"`
	Direction               string   `json:"direction,omitempty"`
	FromEntity              string   `json:"from_entity,omitempty"`
	ToEntity                string   `json:"to_entity,omitempty"`
	FromEntityCategory      string   `json:"from_entity_category,omitempty"`
	ToEntityCategory        string   `json:"to_entity_category,omitempty"`
	FromEntitySource        string   `json:"from_entity_source,omitempty"`
	ToEntitySource          string   `json:"to_entity_source,omitempty"`
	TransferType            string   `json:"transfer_type,omitempty"`
	RiskFlag                string   `json:"risk_flag,omitempty"`
	RiskFlagEndpoint        string   `json:"risk_flag_endpoint,omitempty"`
	RiskFlagAddress         string   `json:"risk_flag_address,omitempty"`
	RiskFlagSource          string   `json:"risk_flag_source,omitempty"`
	Kind                    string   `json:"kind"`
	Amount                  float64  `json:"amount"`
	Slot                    int64    `json:"slot,omitempty"`
	Signature               string   `json:"signature,omitempty"`
	ProgramIDs              []string `json:"program_ids"`
	Evidence                []string `json:"evidence"`
}

// HolderClusterFlowAnalysis summarizes direct holder transfers and repeated
// token exit destinations observed inside the bounded transaction window.
type HolderClusterFlowAnalysis struct {
	Available                  bool                           `json:"available"`
	Status                     string                         `json:"status"`
	Confidence                 string                         `json:"confidence"`
	TransactionsWithOutflow    int                            `json:"transactions_with_outflow"`
	WalletsWithOutflow         int                            `json:"wallets_with_outflow"`
	DEXExitObservationCount    int                            `json:"dex_exit_observation_count"`
	CEXInflowObservationCount  int                            `json:"cex_inflow_observation_count"`
	CEXOutflowObservationCount int                            `json:"cex_outflow_observation_count"`
	RiskFlagObservationCount   int                            `json:"risk_flag_observation_count"`
	CommonExitGroupCount       int                            `json:"common_exit_group_count"`
	LargestCommonExitGroup     int                            `json:"largest_common_exit_group"`
	InternalTransferCount      int                            `json:"internal_transfer_count"`
	CircularWalletCount        int                            `json:"circular_wallet_count"`
	LinkedHolderPercentage     float64                        `json:"linked_holder_percentage"`
	RiskContribution           int                            `json:"risk_contribution"`
	LinkedWallets              []string                       `json:"linked_wallets"`
	CircularWallets            []string                       `json:"circular_wallets"`
	CommonExitGroups           []HolderClusterGroup           `json:"common_exit_groups"`
	InternalTransfers          []HolderClusterFlowObservation `json:"internal_transfers"`
	Observations               []HolderClusterFlowObservation `json:"observations"`
	Findings                   []string                       `json:"findings"`
	Limitations                []string                       `json:"limitations"`
}

func observeHolderClusterWalletFlow(tx map[string]any, signature, mint, holderWallet string, holderWallets map[string]bool) []HolderClusterFlowObservation {
	deltas := holderClusterTokenOwnerDeltas(tx, mint)
	holderDelta := deltas[holderWallet]
	switch {
	case holderDelta < -holderClusterFlowEpsilon:
		return holderClusterOutboundObservations(tx, signature, mint, holderWallet, holderWallets, deltas, holderDelta)
	case holderDelta > holderClusterFlowEpsilon:
		return holderClusterInboundObservations(tx, signature, mint, holderWallet, holderWallets, deltas, holderDelta)
	default:
		return []HolderClusterFlowObservation{}
	}
}

func holderClusterOutboundObservations(tx map[string]any, signature, mint, sourceWallet string, holderWallets map[string]bool, deltas map[string]float64, sourceDelta float64) []HolderClusterFlowObservation {
	programIDs := holderClusterKnownExitPrograms(tx)
	slot := holderClusterInt64(tx["slot"])
	out := []HolderClusterFlowObservation{}
	seen := map[string]bool{}
	for destination, delta := range deltas {
		if strings.EqualFold(destination, sourceWallet) || delta <= holderClusterFlowEpsilon {
			continue
		}
		kind := "external_token_recipient"
		if holderWallets[destination] {
			kind = "holder_to_holder"
		}
		amount := math.Min(-sourceDelta, delta)
		key := kind + "|" + destination + "|" + signature
		if seen[key] {
			continue
		}
		seen[key] = true
		sourceTokenAccount, destinationTokenAccount, decimals := holderClusterDirectTransferMetadata(tx, mint, sourceWallet, destination)
		observation := HolderClusterFlowObservation{
			SourceWallet:            sourceWallet,
			Destination:             destination,
			Mint:                    strings.TrimSpace(mint),
			SourceTokenAccount:      sourceTokenAccount,
			DestinationTokenAccount: destinationTokenAccount,
			Decimals:                decimals,
			Direction:               "outbound",
			Kind:                    kind,
			Amount:                  holderClusterRound(amount, 9),
			Slot:                    slot,
			Signature:               signature,
			ProgramIDs:              append([]string{}, programIDs...),
			Evidence: []string{
				fmt.Sprintf("Target-token balance decreased for %s while %s increased in the same parsed transaction.", sourceWallet, destination),
			},
		}
		if sourceTokenAccount != "" && destinationTokenAccount != "" {
			observation.Evidence = append(observation.Evidence, "The parsed token instruction resolved both source and destination token accounts to their controlling owner wallets.")
		}
		if len(programIDs) > 0 {
			observation.Evidence = append(observation.Evidence, "Known pool/DEX program context was present; this is route context, not proof of a sale or common ownership.")
		}
		out = append(out, observation)
	}

	// A known pool program with a negative owner delta is useful route context,
	// even when RPC token-balance rows do not expose a recipient owner. Program
	// identity alone is deliberately excluded from common-exit scoring.
	if len(out) == 0 && len(programIDs) > 0 {
		sourceTokenAccount, decimals := holderClusterUniqueOwnerTokenAccount(tx, mint, sourceWallet)
		out = append(out, HolderClusterFlowObservation{
			SourceWallet:       sourceWallet,
			Destination:        programIDs[0],
			Mint:               strings.TrimSpace(mint),
			SourceTokenAccount: sourceTokenAccount,
			Decimals:           decimals,
			Direction:          "outbound",
			Kind:               "dex_program_exit_context",
			Amount:             holderClusterRound(-sourceDelta, 9),
			Slot:               slot,
			Signature:          signature,
			ProgramIDs:         append([]string{}, programIDs...),
			Evidence: []string{
				"A negative target-token balance delta was observed with known pool/DEX program context, but no recipient owner was exposed by the bounded RPC response.",
			},
		})
	}
	return out
}

func holderClusterInboundObservations(tx map[string]any, signature, mint, destinationWallet string, holderWallets map[string]bool, deltas map[string]float64, destinationDelta float64) []HolderClusterFlowObservation {
	programIDs := holderClusterKnownExitPrograms(tx)
	slot := holderClusterInt64(tx["slot"])
	out := []HolderClusterFlowObservation{}
	seen := map[string]bool{}
	for source, delta := range deltas {
		if strings.EqualFold(source, destinationWallet) || delta >= -holderClusterFlowEpsilon {
			continue
		}
		kind := "inbound_token_sender_context"
		if holderWallets[source] {
			kind = "holder_to_holder_inbound_context"
		}
		amount := math.Min(destinationDelta, -delta)
		key := kind + "|" + source + "|" + signature
		if seen[key] {
			continue
		}
		seen[key] = true
		sourceTokenAccount, destinationTokenAccount, decimals := holderClusterDirectTransferMetadata(tx, mint, source, destinationWallet)
		observation := HolderClusterFlowObservation{
			SourceWallet:            source,
			Destination:             destinationWallet,
			Mint:                    strings.TrimSpace(mint),
			SourceTokenAccount:      sourceTokenAccount,
			DestinationTokenAccount: destinationTokenAccount,
			Decimals:                decimals,
			Direction:               "inbound",
			Kind:                    kind,
			Amount:                  holderClusterRound(amount, 9),
			Slot:                    slot,
			Signature:               signature,
			ProgramIDs:              append([]string{}, programIDs...),
			Evidence: []string{
				fmt.Sprintf("Target-token balance increased for %s while %s decreased in the same parsed transaction.", destinationWallet, source),
				"Inbound context is preserved for entity direction classification and is excluded from common-exit and circular-flow scoring.",
			},
		}
		if sourceTokenAccount != "" && destinationTokenAccount != "" {
			observation.Evidence = append(observation.Evidence, "The parsed token instruction resolved both source and destination token accounts to their controlling owner wallets.")
		}
		out = append(out, observation)
	}
	if len(out) == 0 && len(programIDs) > 0 {
		destinationTokenAccount, decimals := holderClusterUniqueOwnerTokenAccount(tx, mint, destinationWallet)
		out = append(out, HolderClusterFlowObservation{
			SourceWallet:            programIDs[0],
			Destination:             destinationWallet,
			Mint:                    strings.TrimSpace(mint),
			DestinationTokenAccount: destinationTokenAccount,
			Decimals:                decimals,
			Direction:               "inbound",
			Kind:                    "dex_program_inflow_context",
			Amount:                  holderClusterRound(destinationDelta, 9),
			Slot:                    slot,
			Signature:               signature,
			ProgramIDs:              append([]string{}, programIDs...),
			Evidence: []string{
				"A positive target-token balance delta was observed with known pool/DEX program context, but no sender owner was exposed by the bounded RPC response.",
				"Inbound DEX context is excluded from common-exit and circular-flow scoring.",
			},
		})
	}
	return out
}

type holderClusterFlowTokenAccount struct {
	Owner    string
	Mint     string
	Decimals *int
}

func holderClusterDirectTransferMetadata(tx map[string]any, mint, sourceWallet, destinationWallet string) (string, string, *int) {
	meta := holderClusterMap(tx["meta"])
	message := holderClusterMap(holderClusterMap(tx["transaction"])["message"])
	keys := holderClusterAccountKeys(message["accountKeys"])
	accounts := holderClusterFlowTokenAccounts(meta, keys)
	for _, instruction := range holderClusterFlowInstructions(message, meta) {
		parsed := holderClusterMap(instruction["parsed"])
		kind := strings.ToLower(strings.TrimSpace(holderClusterString(parsed["type"])))
		if kind != "transfer" && kind != "transferchecked" {
			continue
		}
		info := holderClusterMap(parsed["info"])
		sourceAccount := strings.TrimSpace(holderClusterString(info["source"]))
		destinationAccount := strings.TrimSpace(holderClusterString(info["destination"]))
		if sourceAccount == "" || destinationAccount == "" {
			continue
		}
		source := accounts[sourceAccount]
		destination := accounts[destinationAccount]
		transferMint := strings.TrimSpace(holderClusterString(info["mint"]))
		if transferMint == "" {
			transferMint = firstNonEmptyString(source.Mint, destination.Mint)
		}
		if !strings.EqualFold(transferMint, mint) || !strings.EqualFold(source.Owner, sourceWallet) || !strings.EqualFold(destination.Owner, destinationWallet) {
			continue
		}
		decimals := holderClusterFlowInstructionDecimals(info)
		if decimals == nil {
			decimals = firstHolderClusterDecimals(source.Decimals, destination.Decimals)
		}
		return sourceAccount, destinationAccount, decimals
	}
	return "", "", nil
}

func holderClusterUniqueOwnerTokenAccount(tx map[string]any, mint, owner string) (string, *int) {
	meta := holderClusterMap(tx["meta"])
	message := holderClusterMap(holderClusterMap(tx["transaction"])["message"])
	accounts := holderClusterFlowTokenAccounts(meta, holderClusterAccountKeys(message["accountKeys"]))
	matches := []string{}
	var decimals *int
	for account, item := range accounts {
		if !strings.EqualFold(item.Mint, mint) || !strings.EqualFold(item.Owner, owner) {
			continue
		}
		matches = append(matches, account)
		decimals = firstHolderClusterDecimals(decimals, item.Decimals)
	}
	if len(matches) != 1 {
		return "", decimals
	}
	return matches[0], decimals
}

func holderClusterFlowTokenAccounts(meta map[string]any, keys []string) map[string]holderClusterFlowTokenAccount {
	out := map[string]holderClusterFlowTokenAccount{}
	collect := func(raw any) {
		for _, item := range holderClusterSlice(raw) {
			row := holderClusterMap(item)
			rawIndex, ok := row["accountIndex"]
			if !ok {
				continue
			}
			index := int(holderClusterInt64(rawIndex))
			if index < 0 || index >= len(keys) || strings.TrimSpace(keys[index]) == "" {
				continue
			}
			current := out[keys[index]]
			if owner := strings.TrimSpace(holderClusterString(row["owner"])); owner != "" {
				current.Owner = owner
			}
			if mint := strings.TrimSpace(holderClusterString(row["mint"])); mint != "" {
				current.Mint = mint
			}
			amount := holderClusterMap(row["uiTokenAmount"])
			if rawDecimals, ok := amount["decimals"]; ok {
				value := int(holderClusterInt64(rawDecimals))
				current.Decimals = &value
			}
			out[keys[index]] = current
		}
	}
	collect(meta["preTokenBalances"])
	collect(meta["postTokenBalances"])
	return out
}

func holderClusterFlowInstructions(message, meta map[string]any) []map[string]any {
	out := []map[string]any{}
	appendRows := func(raw any) {
		for _, item := range holderClusterSlice(raw) {
			if row := holderClusterMap(item); len(row) > 0 {
				out = append(out, row)
			}
		}
	}
	appendRows(message["instructions"])
	for _, item := range holderClusterSlice(meta["innerInstructions"]) {
		appendRows(holderClusterMap(item)["instructions"])
	}
	return out
}

func holderClusterFlowInstructionDecimals(info map[string]any) *int {
	tokenAmount := holderClusterMap(info["tokenAmount"])
	if raw, ok := tokenAmount["decimals"]; ok {
		value := int(holderClusterInt64(raw))
		return &value
	}
	if raw, ok := info["decimals"]; ok {
		value := int(holderClusterInt64(raw))
		return &value
	}
	return nil
}

func firstHolderClusterDecimals(values ...*int) *int {
	for _, value := range values {
		if value == nil {
			continue
		}
		copy := *value
		return &copy
	}
	return nil
}

func summarizeHolderClusterFlow(wallets []HolderClusterWallet) HolderClusterFlowAnalysis {
	out := HolderClusterFlowAnalysis{
		Status:            "insufficient_evidence",
		Confidence:        "none",
		LinkedWallets:     []string{},
		CircularWallets:   []string{},
		CommonExitGroups:  []HolderClusterGroup{},
		InternalTransfers: []HolderClusterFlowObservation{},
		Observations:      []HolderClusterFlowObservation{},
		Findings:          []string{},
		Limitations:       []string{},
	}
	walletPct := map[string]float64{}
	holderSet := map[string]bool{}
	for _, wallet := range wallets {
		walletPct[wallet.Wallet] = wallet.HolderPercentage
		holderSet[wallet.Wallet] = true
		out.Observations = append(out.Observations, wallet.FlowObservations...)
	}
	if len(out.Observations) == 0 {
		out.Limitations = append(out.Limitations, "No parsed target-token transfer relation was observed in the bounded holder transaction window.")
		return out
	}

	out.Available = true
	out.Status = "verified_bounded_holder_flow_observation"
	outgoingWallets := map[string]bool{}
	outflowTransactions := map[string]bool{}
	commonExitSources := map[string]map[string]bool{}
	internalSeen := map[string]bool{}
	for _, observation := range out.Observations {
		switch observation.TransferType {
		case "CEX_IN":
			out.CEXInflowObservationCount++
		case "CEX_OUT":
			out.CEXOutflowObservationCount++
		}
		if observation.RiskFlag != "" {
			out.RiskFlagObservationCount++
		}
		if holderFlowObservationDirection(observation) == "inbound" {
			continue
		}
		outgoingWallets[observation.SourceWallet] = true
		if observation.Signature != "" {
			outflowTransactions[observation.Signature] = true
		}
		if holderFlowObservationIsDEX(observation) {
			out.DEXExitObservationCount++
		}
		switch observation.Kind {
		case "holder_to_holder":
			key := observation.SourceWallet + "|" + observation.Destination + "|" + observation.Signature
			if !internalSeen[key] {
				internalSeen[key] = true
				out.InternalTransfers = append(out.InternalTransfers, observation)
			}
		case "external_token_recipient":
			// A positively-resolved CEX destination or a known DEX/pool route is
			// retained as flow context but is not treated as common-control evidence.
			if holderFlowObservationIsDEX(observation) || observation.TransferType == "CEX_OUT" {
				continue
			}
			if commonExitSources[observation.Destination] == nil {
				commonExitSources[observation.Destination] = map[string]bool{}
			}
			commonExitSources[observation.Destination][observation.SourceWallet] = true
		}
	}
	out.WalletsWithOutflow = len(outgoingWallets)
	out.TransactionsWithOutflow = len(outflowTransactions)
	out.InternalTransferCount = len(out.InternalTransfers)

	for destination, sourceSet := range commonExitSources {
		if len(sourceSet) < 2 {
			continue
		}
		wallets := make([]string, 0, len(sourceSet))
		groupPct := 0.0
		for wallet := range sourceSet {
			wallets = append(wallets, wallet)
			groupPct += walletPct[wallet]
		}
		sort.Strings(wallets)
		group := HolderClusterGroup{
			Key:              destination,
			Wallets:          wallets,
			MemberCount:      len(wallets),
			HolderPercentage: holderClusterRound(groupPct, 4),
			Evidence: []string{
				fmt.Sprintf("%d holder wallets sent the target token to the same observed recipient owner in bounded parsed transactions.", len(wallets)),
			},
		}
		out.CommonExitGroups = append(out.CommonExitGroups, group)
		if group.MemberCount > out.LargestCommonExitGroup {
			out.LargestCommonExitGroup = group.MemberCount
		}
	}
	sort.SliceStable(out.CommonExitGroups, func(i, j int) bool {
		if out.CommonExitGroups[i].MemberCount == out.CommonExitGroups[j].MemberCount {
			return out.CommonExitGroups[i].HolderPercentage > out.CommonExitGroups[j].HolderPercentage
		}
		return out.CommonExitGroups[i].MemberCount > out.CommonExitGroups[j].MemberCount
	})
	out.CommonExitGroupCount = len(out.CommonExitGroups)
	out.CircularWallets = holderClusterCircularWallets(out.InternalTransfers)
	out.CircularWalletCount = len(out.CircularWallets)

	linked := map[string]bool{}
	for _, group := range out.CommonExitGroups {
		for _, wallet := range group.Wallets {
			linked[wallet] = true
		}
	}
	for _, observation := range out.InternalTransfers {
		linked[observation.SourceWallet] = true
		if holderSet[observation.Destination] {
			linked[observation.Destination] = true
		}
	}
	for _, wallet := range out.CircularWallets {
		linked[wallet] = true
	}
	for wallet := range linked {
		out.LinkedWallets = append(out.LinkedWallets, wallet)
		out.LinkedHolderPercentage += walletPct[wallet]
	}
	sort.Strings(out.LinkedWallets)
	out.LinkedHolderPercentage = holderClusterRound(out.LinkedHolderPercentage, 4)

	score := 0
	switch {
	case out.LargestCommonExitGroup >= 4:
		score += 22
	case out.LargestCommonExitGroup >= 3:
		score += 15
	case out.LargestCommonExitGroup >= 2:
		score += 7
	}
	switch {
	case out.InternalTransferCount >= 4:
		score += 16
	case out.InternalTransferCount >= 2:
		score += 10
	case out.InternalTransferCount >= 1:
		score += 4
	}
	if out.CircularWalletCount >= 2 {
		score += 18
	}
	if out.LargestCommonExitGroup >= 3 && out.InternalTransferCount >= 2 {
		score += 10
	}
	if score > 45 {
		score = 45
	}
	out.RiskContribution = score
	switch {
	case out.CircularWalletCount >= 2 && out.LargestCommonExitGroup >= 2:
		out.Confidence = "high"
	case out.LargestCommonExitGroup >= 2 || out.InternalTransferCount >= 2 || out.CircularWalletCount >= 2:
		out.Confidence = "medium"
	default:
		out.Confidence = "low"
	}
	out.Findings = holderClusterFlowFindings(out)
	out.Limitations = append(out.Limitations,
		"Common exit means the same parsed target-token recipient owner was observed; positively-resolved CEX and known DEX/pool routes are excluded from common-control scoring.",
		"CEX_IN and CEX_OUT require a positive Helius Wallet Identity classification; an unlabeled exchange address remains ordinary inflow/outflow context.",
		"DRAINER, MIXER and SUSPICIOUS flags are emitted only from explicit third-party identity taxonomy labels and do not independently change the flow risk score.",
		"Circular holder-to-holder transfer relations are not labelled wash trading without repeated swap, consideration and return-flow evidence.",
	)
	return out
}

func holderClusterFlowFindings(out HolderClusterFlowAnalysis) []string {
	findings := []string{fmt.Sprintf("Observed %d target-token outflow transactions across %d holder wallets in the bounded window.", out.TransactionsWithOutflow, out.WalletsWithOutflow)}
	if out.CEXOutflowObservationCount > 0 {
		findings = append(findings, fmt.Sprintf("%d target-token transfers were classified as CEX_OUT from positively-resolved destination entities.", out.CEXOutflowObservationCount))
	}
	if out.CEXInflowObservationCount > 0 {
		findings = append(findings, fmt.Sprintf("%d target-token transfers were classified as CEX_IN from positively-resolved source entities.", out.CEXInflowObservationCount))
	}
	if out.RiskFlagObservationCount > 0 {
		findings = append(findings, fmt.Sprintf("%d transfer observations contain an explicit third-party DRAINER, MIXER or SUSPICIOUS endpoint label.", out.RiskFlagObservationCount))
	}
	if out.LargestCommonExitGroup >= 2 {
		findings = append(findings, fmt.Sprintf("The largest verified common-exit recipient group contains %d holder wallets.", out.LargestCommonExitGroup))
	}
	if out.InternalTransferCount > 0 {
		findings = append(findings, fmt.Sprintf("%d direct target-token transfer relations were observed between resolved holder wallets.", out.InternalTransferCount))
	}
	if out.CircularWalletCount >= 2 {
		findings = append(findings, fmt.Sprintf("%d holder wallets participate in a bounded circular transfer relation; this is not, by itself, a wash-trading verdict.", out.CircularWalletCount))
	}
	if out.LinkedHolderPercentage > 0 {
		findings = append(findings, fmt.Sprintf("Flow-linked holder wallets represent approximately %.4f%% of role-adjusted holder supply.", out.LinkedHolderPercentage))
	}
	if len(findings) == 1 {
		findings = append(findings, "No repeated common-exit, holder-to-holder or circular transfer pattern was verified in the bounded window.")
	}
	return findings
}

func holderClusterCircularWallets(observations []HolderClusterFlowObservation) []string {
	adjacency := map[string]map[string]bool{}
	for _, observation := range observations {
		if observation.Kind != "holder_to_holder" || observation.SourceWallet == "" || observation.Destination == "" {
			continue
		}
		if adjacency[observation.SourceWallet] == nil {
			adjacency[observation.SourceWallet] = map[string]bool{}
		}
		adjacency[observation.SourceWallet][observation.Destination] = true
	}
	circular := map[string]bool{}
	for start, nextSet := range adjacency {
		for next := range nextSet {
			if holderClusterFlowPathExists(adjacency, next, start, map[string]bool{start: true}) {
				circular[start] = true
				circular[next] = true
			}
		}
	}
	out := make([]string, 0, len(circular))
	for wallet := range circular {
		out = append(out, wallet)
	}
	sort.Strings(out)
	return out
}

func holderClusterFlowPathExists(adjacency map[string]map[string]bool, current, target string, visited map[string]bool) bool {
	if current == target {
		return true
	}
	if visited[current] {
		return false
	}
	visited[current] = true
	for next := range adjacency[current] {
		if holderClusterFlowPathExists(adjacency, next, target, visited) {
			return true
		}
	}
	return false
}

func holderClusterTokenOwnerDeltas(tx map[string]any, mint string) map[string]float64 {
	meta := holderClusterMap(tx["meta"])
	pre := holderClusterTokenOwnerTotals(meta["preTokenBalances"], mint)
	post := holderClusterTokenOwnerTotals(meta["postTokenBalances"], mint)
	out := map[string]float64{}
	for owner, amount := range pre {
		out[owner] -= amount
	}
	for owner, amount := range post {
		out[owner] += amount
	}
	return out
}

func holderClusterTokenOwnerTotals(raw any, mint string) map[string]float64 {
	out := map[string]float64{}
	for _, item := range holderClusterSlice(raw) {
		row := holderClusterMap(item)
		if !strings.EqualFold(holderClusterString(row["mint"]), mint) {
			continue
		}
		owner := strings.TrimSpace(holderClusterString(row["owner"]))
		if owner == "" {
			continue
		}
		amount := holderClusterMap(row["uiTokenAmount"])
		value := holderClusterFloat(amount["uiAmount"])
		if text := holderClusterString(amount["uiAmountString"]); text != "" {
			if parsed, err := strconvParseFloat(text); err == nil {
				value = parsed
			}
		}
		out[owner] += value
	}
	return out
}

func holderClusterKnownExitPrograms(tx map[string]any) []string {
	evidence := arvisTransactionEvidence{TokenBalanceChanges: map[string]float64{}, LamportDeltas: map[string]int64{}}
	parseArvisTransactionMap(tx, &evidence)
	seen := map[string]bool{}
	out := []string{}
	for _, programID := range evidence.ProgramIDs {
		if !isKnownRaydiumProgram(programID) && programID != pumpBondingCurveProgramID && programID != pumpLiquidityProgramID {
			continue
		}
		if !seen[programID] {
			seen[programID] = true
			out = append(out, programID)
		}
	}
	sort.Strings(out)
	return out
}

// Small wrapper keeps parsing behavior aligned with the rest of the service
// without exposing strconv details throughout the flow engine.
func strconvParseFloat(value string) (float64, error) {
	return strconv.ParseFloat(strings.TrimSpace(value), 64)
}
