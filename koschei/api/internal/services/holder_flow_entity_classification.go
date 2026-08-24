package services

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	holderFlowIdentityLookupLimit       = 24
	holderFlowIdentityLookupConcurrency = 4
	holderFlowIdentityLookupTimeout     = 4 * time.Second
)

// enrichHolderClusterFlowObservations attaches positively-resolved Helius
// identity metadata to bounded transfer observations only when the paid-plan
// capability is explicitly enabled. Unknown/disabled addresses remain
// unlabeled; no entity or risk flag is guessed from transfer behavior alone.
func enrichHolderClusterFlowObservations(ctx context.Context, rpcURL string, holderWallets map[string]bool, observations []HolderClusterFlowObservation, budget *holderScanRPCBudget) []HolderClusterFlowObservation {
	if len(observations) == 0 {
		return observations
	}

	labels := map[string]*WalletLabel{}
	pending := []string{}
	seen := map[string]bool{}
	identityLookupAllowed := heliusWalletIdentityEnabled() && !heliusWalletIdentityUnavailable()
	for _, observation := range observations {
		for _, address := range holderFlowIdentityAddresses(observation) {
			if seen[address] {
				continue
			}
			seen[address] = true
			if cached, ok := labelCacheGet(address); ok {
				labels[address] = cached
				continue
			}
			if !identityLookupAllowed {
				continue
			}
			if budget != nil && !budget.ReserveIdentity(1) {
				continue
			}
			pending = append(pending, address)
			if len(pending) >= holderFlowIdentityLookupLimit {
				break
			}
		}
		if len(pending) >= holderFlowIdentityLookupLimit {
			break
		}
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, holderFlowIdentityLookupConcurrency)
	for _, address := range pending {
		address := address
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			lookupCtx, cancel := context.WithTimeout(ctx, holderFlowIdentityLookupTimeout)
			defer cancel()
			label := ResolveWalletLabel(lookupCtx, rpcURL, address)
			mu.Lock()
			labels[address] = label
			mu.Unlock()
		}()
	}
	wg.Wait()

	out := make([]HolderClusterFlowObservation, 0, len(observations))
	for _, observation := range observations {
		from := labels[strings.TrimSpace(observation.SourceWallet)]
		to := labels[strings.TrimSpace(observation.Destination)]
		out = append(out, enrichHolderClusterFlowObservationWithLabels(observation, holderWallets, from, to))
	}
	return out
}

func holderFlowIdentityAddresses(observation HolderClusterFlowObservation) []string {
	out := []string{}
	appendAddress := func(address string) {
		address = strings.TrimSpace(address)
		if !holderFlowLooksLikeSolanaWallet(address) {
			return
		}
		for _, programID := range observation.ProgramIDs {
			if address == strings.TrimSpace(programID) {
				return
			}
		}
		for _, existing := range out {
			if existing == address {
				return
			}
		}
		out = append(out, address)
	}
	appendAddress(observation.SourceWallet)
	if observation.Kind != "token_account_recipient_unresolved" && observation.Kind != "dex_program_exit_context" && observation.Kind != "dex_program_inflow_context" {
		appendAddress(observation.Destination)
	}
	return out
}

func holderFlowLooksLikeSolanaWallet(address string) bool {
	address = strings.TrimSpace(address)
	if len(address) < 32 || len(address) > 44 {
		return false
	}
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	for _, character := range address {
		if !strings.ContainsRune(alphabet, character) {
			return false
		}
	}
	return true
}

func enrichHolderClusterFlowObservationWithLabels(observation HolderClusterFlowObservation, holderWallets map[string]bool, fromLabel, toLabel *WalletLabel) HolderClusterFlowObservation {
	if fromLabel != nil {
		observation.FromEntity = holderFlowEntityName(fromLabel)
		observation.FromEntityCategory = strings.TrimSpace(fromLabel.Category)
		observation.FromEntitySource = strings.TrimSpace(fromLabel.Source)
	}
	if toLabel != nil {
		observation.ToEntity = holderFlowEntityName(toLabel)
		observation.ToEntityCategory = strings.TrimSpace(toLabel.Category)
		observation.ToEntitySource = strings.TrimSpace(toLabel.Source)
	}
	observation.Direction = holderFlowObservationDirection(observation)
	observation.TransferType = classifyHolderClusterTransfer(observation, holderWallets, fromLabel, toLabel)

	fromRisk := holderFlowWalletRiskFlag(fromLabel)
	toRisk := holderFlowWalletRiskFlag(toLabel)
	flag, endpoint, address := holderFlowSelectRiskFlag(fromRisk, toRisk, observation.SourceWallet, observation.Destination)
	if flag != "" {
		observation.RiskFlag = flag
		observation.RiskFlagEndpoint = endpoint
		observation.RiskFlagAddress = strings.TrimSpace(address)
		observation.RiskFlagSource = "helius_identity"
	}

	if observation.FromEntity != "" {
		observation.Evidence = appendUniqueHolderFlowEvidence(observation.Evidence, "Helius Wallet Identity positively resolved the transfer source as "+holderFlowEntityEvidence(fromLabel)+".")
	}
	if observation.ToEntity != "" {
		observation.Evidence = appendUniqueHolderFlowEvidence(observation.Evidence, "Helius Wallet Identity positively resolved the transfer destination as "+holderFlowEntityEvidence(toLabel)+".")
	}
	if observation.TransferType != "" && observation.TransferType != "UNKNOWN" {
		observation.Evidence = appendUniqueHolderFlowEvidence(observation.Evidence, "Koschei classified the observed route as "+observation.TransferType+" from holder membership, program context and positively-resolved entity metadata.")
	}
	if observation.RiskFlag != "" {
		observation.Evidence = appendUniqueHolderFlowEvidence(observation.Evidence, "A third-party Helius identity taxonomy explicitly marked the "+observation.RiskFlagEndpoint+" endpoint as "+observation.RiskFlag+"; this is attribution metadata, not a Koschei intent or real-person identity claim.")
	}
	return observation
}

func classifyHolderClusterTransfer(observation HolderClusterFlowObservation, holderWallets map[string]bool, fromLabel, toLabel *WalletLabel) string {
	from := strings.TrimSpace(observation.SourceWallet)
	to := strings.TrimSpace(observation.Destination)
	fromHolder := holderWallets[from]
	toHolder := holderWallets[to]
	if fromHolder && toHolder {
		return "INTERNAL"
	}
	if holderFlowObservationIsDEX(observation) {
		return "DEX"
	}
	if fromHolder && holderFlowWalletIsCEX(toLabel) {
		return "CEX_OUT"
	}
	if toHolder && holderFlowWalletIsCEX(fromLabel) {
		return "CEX_IN"
	}
	if holderFlowObservationDirection(observation) == "inbound" {
		return "INFLOW"
	}
	if fromHolder {
		return "OUTFLOW"
	}
	return "UNKNOWN"
}

func holderFlowObservationDirection(observation HolderClusterFlowObservation) string {
	direction := strings.ToLower(strings.TrimSpace(observation.Direction))
	if direction == "inbound" || direction == "outbound" {
		return direction
	}
	if strings.Contains(strings.ToLower(observation.Kind), "inbound") || strings.Contains(strings.ToLower(observation.Kind), "inflow") {
		return "inbound"
	}
	return "outbound"
}

func holderFlowObservationIsDEX(observation HolderClusterFlowObservation) bool {
	kind := strings.ToLower(strings.TrimSpace(observation.Kind))
	return len(observation.ProgramIDs) > 0 || strings.Contains(kind, "dex_program")
}

func holderFlowWalletIsCEX(label *WalletLabel) bool {
	if label == nil {
		return false
	}
	for _, value := range holderFlowTaxonomyValues(label) {
		normalized := holderFlowNormalizeTaxonomy(value)
		switch normalized {
		case "cex", "centralized exchange", "centralised exchange", "exchange deposit", "exchange hot wallet", "exchange cold wallet":
			return true
		}
	}
	entity := holderFlowNormalizeTaxonomy(label.Entity)
	known := map[string]bool{
		"binance": true, "coinbase": true, "okx": true, "kraken": true,
		"bybit": true, "kucoin": true, "mexc": true, "bitget": true,
		"gate io": true, "crypto com": true, "htx": true, "upbit": true,
		"bithumb": true, "gemini": true,
	}
	return known[entity]
}

func holderFlowWalletRiskFlag(label *WalletLabel) string {
	if label == nil {
		return ""
	}
	values := []string{label.Category}
	values = append(values, label.Labels...)
	values = append(values, label.Tags...)
	if holderFlowTaxonomyContains(values, []string{"drainer", "wallet drainer", "drain service"}) {
		return "DRAINER"
	}
	if holderFlowTaxonomyContains(values, []string{"mixer", "tumbler", "coinjoin", "tornado cash"}) {
		return "MIXER"
	}
	if holderFlowTaxonomyContains(values, []string{
		"suspicious", "scam", "phishing", "malicious", "exploit", "exploiter",
		"hacker", "fraud", "sanctioned", "stolen funds", "illicit",
	}) {
		return "SUSPICIOUS"
	}
	return ""
}

func holderFlowSelectRiskFlag(fromFlag, toFlag, fromAddress, toAddress string) (string, string, string) {
	priority := map[string]int{"SUSPICIOUS": 1, "MIXER": 2, "DRAINER": 3}
	if priority[toFlag] >= priority[fromFlag] && toFlag != "" {
		return toFlag, "destination", toAddress
	}
	if fromFlag != "" {
		return fromFlag, "source", fromAddress
	}
	return "", "", ""
}

func holderFlowTaxonomyValues(label *WalletLabel) []string {
	if label == nil {
		return nil
	}
	out := []string{label.Category}
	out = append(out, label.Labels...)
	out = append(out, label.Tags...)
	return out
}

func holderFlowTaxonomyContains(values, candidates []string) bool {
	for _, value := range values {
		normalized := holderFlowNormalizeTaxonomy(value)
		for _, candidate := range candidates {
			candidate = holderFlowNormalizeTaxonomy(candidate)
			if normalized == candidate || strings.Contains(" "+normalized+" ", " "+candidate+" ") {
				return true
			}
		}
	}
	return false
}

func holderFlowNormalizeTaxonomy(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("_", " ", "-", " ", "/", " ", ".", " ", ":", " ")
	return strings.Join(strings.Fields(replacer.Replace(value)), " ")
}

func holderFlowEntityName(label *WalletLabel) string {
	if label == nil {
		return ""
	}
	for _, value := range []string{label.Entity, label.Name, label.Category} {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func holderFlowEntityEvidence(label *WalletLabel) string {
	if label == nil {
		return "an unknown entity"
	}
	parts := []string{}
	if name := holderFlowEntityName(label); name != "" {
		parts = append(parts, name)
	}
	if category := strings.TrimSpace(label.Category); category != "" && category != holderFlowEntityName(label) {
		parts = append(parts, category)
	}
	if len(parts) == 0 {
		return "an unlabeled entity"
	}
	return strings.Join(parts, " · ")
}

func appendUniqueHolderFlowEvidence(items []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return items
	}
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func sortedHolderFlowKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
