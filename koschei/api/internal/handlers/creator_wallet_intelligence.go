package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type creatorIntelFlow struct {
	Wallet       string
	Amount       float64
	Transactions int
	FirstAt      int64
	LastAt       int64
}

type creatorIntelHolderResult struct {
	Status             string
	Accounts           []map[string]any
	OwnerIndex         map[string]map[string]any
	CreatorIsTopHolder bool
	CreatorRank        int
	CreatorPercentage  float64
}

// OwnerCreatorIntelligence continues a Radar investigation after a launch
// source identifies a creator/deployer wallet. It inspects Koschei-observed
// launches, bounded recent on-chain history, token outflow, recipient wallets,
// funding wallets and Top-20 holder-owner links.
func (h *Handler) OwnerCreatorIntelligence(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(firstNonEmptyString(r.URL.Query().Get("target"), r.URL.Query().Get("mint")))
	if target == "" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "target is required")
		return
	}
	network := strings.TrimSpace(r.URL.Query().Get("network"))
	if network == "" {
		network = "solana-mainnet"
	}
	source := h.radarDetailSourceContext(r.Context(), target, network)
	creator := strings.TrimSpace(firstNonEmptyString(r.URL.Query().Get("creator"), creatorIntelCleanString(source["creator_wallet"])))
	if creator == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "intelligence": map[string]any{
			"available": false,
			"target":    target,
			"status":    "creator_wallet_not_observed",
			"summary":   "Creator/deployer cüzdanı doğrulanamadığı için davranış analizi çalıştırılmadı.",
		}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(services.LoadArvisScanBudgets().CreatorTimeoutSeconds)*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "intelligence": h.buildCreatorWalletIntelligence(ctx, target, network, creator, source)})
}

func (h *Handler) buildCreatorWalletIntelligence(ctx context.Context, target, network, creator string, source map[string]any) map[string]any {
	launches, launchAt := h.creatorIntelObservedLaunches(ctx, target, network, creator)
	holders := creatorIntelHolderOwners(ctx, target, creator)
	result := map[string]any{
		"available":                 true,
		"target":                    target,
		"network":                   network,
		"creator_wallet":            creator,
		"source":                    creatorIntelCleanString(source["source"]),
		"checked_at":                time.Now().UTC().Format(time.RFC3339),
		"observed_launches":         launches,
		"observed_launch_count":     len(launches),
		"previous_launch_count":     creatorIntelPreviousLaunchCount(launches, target),
		"holder_accounts":           holders.Accounts,
		"creator_is_top_holder":     holders.CreatorIsTopHolder,
		"creator_holder_rank":       holders.CreatorRank,
		"creator_holder_percentage": creatorIntelRound(holders.CreatorPercentage, 4),
		"holder_resolution_status":  holders.Status,
		"evidence_scope":            "Koschei-observed launches plus bounded recent Solana RPC history; wallet relations are not proof of wrongdoing or real-world identity.",
	}

	rpcURL := creatorIntelRPCURL()
	if rpcURL == "" {
		return creatorIntelFinalizePartial(result, holders, "Solana RPC yapılandırılmadığı için yakın işlem, satış, transfer ve funding davranışı incelenemedi.")
	}
	result["rpc_available"] = true
	signatures, err := services.SolanaGetSignaturesForAddress(ctx, rpcURL, creator, 40)
	if err != nil {
		result["rpc_error"] = creatorIntelCompactError(err)
		return creatorIntelFinalizePartial(result, holders, "Creator cüzdanının son işlem imzaları RPC sağlayıcısından alınamadı.")
	}

	recipients := map[string]*creatorIntelFlow{}
	funders := map[string]*creatorIntelFlow{}
	transactions := make([]map[string]any, 0, 12)
	checked, saleLike, earlySale, transferOut, launchLike := 0, 0, 0, 0, 0
	currentTokenOutflow := 0.0

	for _, signature := range signatures {
		if checked >= 12 || ctx.Err() != nil {
			break
		}
		if signature.Err != nil || strings.TrimSpace(signature.Signature) == "" {
			continue
		}
		tx, txErr := services.SolanaGetTransactionJSONParsed(ctx, rpcURL, signature.Signature)
		if txErr != nil {
			continue
		}
		checked++
		txMap := map[string]any(tx)
		meta := creatorIntelMap(txMap["meta"])
		message := creatorIntelMap(creatorIntelMap(txMap["transaction"])["message"])
		blockTime := creatorIntelInt64(txMap["blockTime"])
		accountKeys, signers := creatorIntelAccountKeys(message)
		instructionTypes, instructionMints := creatorIntelInstructions(message, meta)
		logs := strings.ToLower(strings.Join(creatorIntelStringSlice(meta["logMessages"]), "\n"))
		swapRelated := creatorIntelSwapRelated(logs, instructionTypes)
		launchRelated := creatorIntelLaunchRelated(logs, instructionTypes)
		if launchRelated && creatorIntelContains(signers, creator) {
			launchLike++
		}

		deltas := creatorIntelOwnerTokenDeltas(meta, target)
		creatorDelta := deltas[creator]
		classification := "observed"
		if creatorDelta < -0.000001 {
			currentTokenOutflow += math.Abs(creatorDelta)
			if swapRelated {
				saleLike++
				classification = "sale_like_outflow"
				if !launchAt.IsZero() && blockTime > 0 {
					observed := time.Unix(blockTime, 0).UTC()
					if !observed.Before(launchAt.Add(-2*time.Minute)) && observed.Before(launchAt.Add(24*time.Hour)) {
						earlySale++
						classification = "early_sale_like_outflow"
					}
				}
			} else {
				transferOut++
				classification = "token_transfer_out"
			}
			for wallet, delta := range deltas {
				if wallet != creator && delta > 0.000001 {
					creatorIntelAccumulateFlow(recipients, wallet, delta, blockTime)
				}
			}
		}

		lamportDeltas := creatorIntelLamportDeltas(meta, accountKeys)
		if lamportDeltas[creator] > 10000 {
			for wallet, delta := range lamportDeltas {
				if wallet != creator && delta < -10000 {
					creatorIntelAccumulateFlow(funders, wallet, float64(-delta)/1e9, blockTime)
				}
			}
		}

		if creatorDelta != 0 || swapRelated || launchRelated {
			transactions = append(transactions, map[string]any{
				"signature":           signature.Signature,
				"block_time":          blockTime,
				"observed_at":         creatorIntelUnixTime(blockTime),
				"creator_signed":      creatorIntelContains(signers, creator),
				"creator_token_delta": creatorIntelRound(creatorDelta, 8),
				"classification":      classification,
				"swap_related":        swapRelated,
				"launch_related":      launchRelated,
				"instruction_types":   instructionTypes,
				"token_mints":         instructionMints,
			})
		}
	}

	recipientRows := creatorIntelFlowRows(recipients, holders.OwnerIndex)
	funderRows := creatorIntelFlowRows(funders, nil)
	holderLinks := creatorIntelHolderLinks(recipientRows)
	result["status"] = "complete"
	result["recent_signatures_seen"] = len(signatures)
	result["recent_transactions_checked"] = checked
	result["rpc_launch_like_transactions"] = launchLike
	result["sale_like_transactions"] = saleLike
	result["early_sale_like_transactions"] = earlySale
	result["transfer_out_transactions"] = transferOut
	result["current_token_outflow"] = creatorIntelRound(currentTokenOutflow, 8)
	result["recipient_wallets"] = recipientRows
	result["funding_wallets"] = funderRows
	result["holder_links"] = holderLinks
	result["transactions"] = transactions
	result["ruleset_version"] = "actor-investigation-v1.0"
	result["unified_radar_ruleset_version"] = "unified-radar-v1.0"
	result["risk_impact"] = "determined_by_unified_ruleset"
	result["findings"] = creatorIntelFindings(result, saleLike, earlySale, transferOut, len(holderLinks), holders, recipientRows)
	result["summary"] = creatorIntelSummary(result)
	result["limitations"] = []string{
		"İşlem incelemesi son 40 imza ve en fazla 12 başarılı transaction ile sınırlandırılmıştır.",
		"Sale-like sınıflandırması token çıkışı ile swap/pool program izlerini birlikte arar; tek başına borsa satışı ispatı değildir.",
		"Koschei'nin daha önce gözlemlemediği eski launchlar observed launch sayısına dahil olmayabilir.",
	}
	return result
}

func creatorIntelFinalizePartial(result map[string]any, holders creatorIntelHolderResult, limitation string) map[string]any {
	result["rpc_available"] = false
	result["status"] = "partial"
	result["ruleset_version"] = "actor-investigation-v1.0"
	result["unified_radar_ruleset_version"] = "unified-radar-v1.0"
	result["risk_impact"] = "determined_by_unified_ruleset"
	result["findings"] = creatorIntelFindings(result, 0, 0, 0, 0, holders, nil)
	result["summary"] = creatorIntelSummary(result)
	result["limitations"] = []string{limitation}
	return result
}

func creatorIntelHolderOwners(ctx context.Context, target, creator string) creatorIntelHolderResult {
	out := creatorIntelHolderResult{Status: "unavailable", Accounts: []map[string]any{}, OwnerIndex: map[string]map[string]any{}}
	rpcURL := creatorIntelRPCURL()
	if rpcURL == "" {
		return out
	}
	supply, err := services.SolanaGetTokenSupply(ctx, rpcURL, target)
	if err != nil {
		out.Status = "supply_unavailable"
		return out
	}
	largest, err := services.SolanaGetTokenLargestAccounts(ctx, rpcURL, target)
	if err != nil {
		out.Status = "largest_accounts_unavailable"
		return out
	}
	total := creatorIntelTokenAmount(supply.Value)
	if total <= 0 {
		out.Status = "invalid_supply"
		return out
	}
	addresses := []string{}
	for i, account := range largest.Value {
		if i >= 20 {
			break
		}
		addresses = append(addresses, account.Address)
	}
	if len(addresses) == 0 {
		out.Status = "no_holder_accounts"
		return out
	}
	resolved, err := services.SolanaGetMultipleAccountsJSONParsed(ctx, rpcURL, addresses)
	if err != nil {
		out.Status = "holder_owner_resolution_unavailable"
		return out
	}
	for i, address := range addresses {
		balance := creatorIntelTokenAmount(largest.Value[i].SolanaTokenAmount)
		pct := balance / total * 100
		owner := ""
		if i < len(resolved.Value) && resolved.Value[i] != nil {
			owner = creatorIntelParsedTokenOwner(resolved.Value[i].Data)
		}
		row := map[string]any{"rank": i + 1, "token_account": address, "owner_wallet": owner, "balance": creatorIntelRound(balance, 8), "percentage": creatorIntelRound(pct, 4)}
		out.Accounts = append(out.Accounts, row)
		if owner != "" {
			out.OwnerIndex[owner] = row
		}
		if owner == creator {
			out.CreatorIsTopHolder = true
			out.CreatorRank = i + 1
			out.CreatorPercentage += pct
		}
	}
	out.Status = "verified_rpc_observation"
	return out
}

func (h *Handler) creatorIntelObservedLaunches(ctx context.Context, target, network, creator string) ([]map[string]any, time.Time) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil || !ownerTableExists(ctx, db, "security_radar_events") {
		return []map[string]any{}, time.Time{}
	}
	rows, err := db.QueryContext(ctx, `
		SELECT target, min(created_at), max(COALESCE(source,'')), max(COALESCE(signature,'')), count(*)
		FROM security_radar_events
		WHERE network=$2 AND (
			COALESCE(signals->>'creator_wallet','')=$1
			OR COALESCE(signals->>'deployer_wallet','')=$1
			OR (COALESCE(source_address,'')=$1 AND lower(COALESCE(source,''))='pumpportal')
		)
		GROUP BY target
		ORDER BY min(created_at) DESC
		LIMIT 50`, creator, network)
	if err != nil {
		return []map[string]any{}, time.Time{}
	}
	defer rows.Close()
	items := []map[string]any{}
	var current time.Time
	for rows.Next() {
		var mint, source, signature string
		var observed time.Time
		var eventCount int64
		if rows.Scan(&mint, &observed, &source, &signature, &eventCount) != nil {
			continue
		}
		items = append(items, map[string]any{"target": mint, "observed_at": observed.UTC(), "source": source, "signature": signature, "event_count": eventCount, "is_current_target": mint == target})
		if mint == target {
			current = observed.UTC()
		}
	}
	return items, current
}

func creatorIntelOwnerTokenDeltas(meta map[string]any, target string) map[string]float64 {
	pre := creatorIntelOwnerTokenTotals(meta["preTokenBalances"], target)
	post := creatorIntelOwnerTokenTotals(meta["postTokenBalances"], target)
	out := map[string]float64{}
	for owner, value := range pre {
		out[owner] -= value
	}
	for owner, value := range post {
		out[owner] += value
	}
	return out
}

func creatorIntelOwnerTokenTotals(raw any, target string) map[string]float64 {
	out := map[string]float64{}
	items, _ := raw.([]any)
	for _, rawItem := range items {
		item := creatorIntelMap(rawItem)
		if creatorIntelCleanString(item["mint"]) != target {
			continue
		}
		owner := creatorIntelCleanString(item["owner"])
		if owner != "" {
			out[owner] += creatorIntelUIAmount(creatorIntelMap(item["uiTokenAmount"]))
		}
	}
	return out
}

func creatorIntelInstructions(message, meta map[string]any) ([]string, []string) {
	types, mints := map[string]bool{}, map[string]bool{}
	creatorIntelCollectInstructions(message["instructions"], types, mints)
	inner, _ := meta["innerInstructions"].([]any)
	for _, raw := range inner {
		creatorIntelCollectInstructions(creatorIntelMap(raw)["instructions"], types, mints)
	}
	typeRows, mintRows := make([]string, 0, len(types)), make([]string, 0, len(mints))
	for value := range types {
		typeRows = append(typeRows, value)
	}
	for value := range mints {
		mintRows = append(mintRows, value)
	}
	sort.Strings(typeRows)
	sort.Strings(mintRows)
	return typeRows, mintRows
}

func creatorIntelCollectInstructions(raw any, types, mints map[string]bool) {
	items, _ := raw.([]any)
	for _, rawItem := range items {
		parsed := creatorIntelMap(creatorIntelMap(rawItem)["parsed"])
		kind := strings.ToLower(creatorIntelCleanString(parsed["type"]))
		if kind != "" {
			types[kind] = true
		}
		info := creatorIntelMap(parsed["info"])
		for _, key := range []string{"mint", "tokenMint", "mintAddress"} {
			if value := creatorIntelCleanString(info[key]); value != "" {
				mints[value] = true
			}
		}
	}
}

func creatorIntelAccountKeys(message map[string]any) ([]string, []string) {
	keys, signers := []string{}, []string{}
	items, _ := message["accountKeys"].([]any)
	for _, raw := range items {
		key, signer := "", false
		switch value := raw.(type) {
		case string:
			key = strings.TrimSpace(value)
		case map[string]any:
			key = creatorIntelCleanString(value["pubkey"])
			signer, _ = value["signer"].(bool)
		}
		if key == "" {
			continue
		}
		keys = append(keys, key)
		if signer {
			signers = append(signers, key)
		}
	}
	return keys, signers
}

func creatorIntelLamportDeltas(meta map[string]any, keys []string) map[string]int64 {
	out := map[string]int64{}
	pre, _ := meta["preBalances"].([]any)
	post, _ := meta["postBalances"].([]any)
	limit := len(keys)
	if len(pre) < limit {
		limit = len(pre)
	}
	if len(post) < limit {
		limit = len(post)
	}
	for i := 0; i < limit; i++ {
		out[keys[i]] = creatorIntelInt64(post[i]) - creatorIntelInt64(pre[i])
	}
	return out
}

func creatorIntelSwapRelated(logs string, instructionTypes []string) bool {
	if strings.Contains(logs, "swap") || strings.Contains(logs, "raydium") || strings.Contains(logs, "pumpswap") || strings.Contains(logs, "sell") {
		return true
	}
	for _, kind := range instructionTypes {
		if strings.Contains(kind, "swap") || strings.Contains(kind, "sell") {
			return true
		}
	}
	return false
}

func creatorIntelLaunchRelated(logs string, instructionTypes []string) bool {
	for _, kind := range instructionTypes {
		if strings.Contains(kind, "initializemint") {
			return true
		}
	}
	return strings.Contains(logs, "pump") && (strings.Contains(logs, "create") || strings.Contains(logs, "initialize"))
}

func creatorIntelAccumulateFlow(items map[string]*creatorIntelFlow, wallet string, amount float64, blockTime int64) {
	wallet = strings.TrimSpace(wallet)
	if wallet == "" {
		return
	}
	row := items[wallet]
	if row == nil {
		row = &creatorIntelFlow{Wallet: wallet, FirstAt: blockTime, LastAt: blockTime}
		items[wallet] = row
	}
	row.Amount += amount
	row.Transactions++
	if row.FirstAt == 0 || (blockTime > 0 && blockTime < row.FirstAt) {
		row.FirstAt = blockTime
	}
	if blockTime > row.LastAt {
		row.LastAt = blockTime
	}
}

func creatorIntelFlowRows(items map[string]*creatorIntelFlow, holderIndex map[string]map[string]any) []map[string]any {
	rows := make([]map[string]any, 0, len(items))
	for _, item := range items {
		row := map[string]any{
			"wallet":             item.Wallet,
			"amount":             creatorIntelRound(item.Amount, 8),
			"transactions":       item.Transactions,
			"first_observed_at":  creatorIntelUnixTime(item.FirstAt),
			"last_observed_at":   creatorIntelUnixTime(item.LastAt),
			"matches_top_holder": false,
		}
		if holderIndex != nil {
			if holder, ok := holderIndex[item.Wallet]; ok {
				row["matches_top_holder"] = true
				row["holder_rank"] = holder["rank"]
				row["holder_percentage"] = holder["percentage"]
			}
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return creatorIntelFloat(rows[i]["amount"]) > creatorIntelFloat(rows[j]["amount"])
	})
	if len(rows) > 20 {
		rows = rows[:20]
	}
	return rows
}

func creatorIntelHolderLinks(recipients []map[string]any) []map[string]any {
	out := []map[string]any{}
	for _, row := range recipients {
		if matched, _ := row["matches_top_holder"].(bool); matched {
			out = append(out, row)
		}
	}
	return out
}

func creatorIntelFindings(result map[string]any, saleLike, earlySale, transferOut, holderLinks int, holders creatorIntelHolderResult, recipients []map[string]any) []string {
	findings := []string{}
	previous := creatorIntelInt(result["previous_launch_count"])
	if previous > 0 {
		findings = append(findings, fmt.Sprintf("Koschei gözlemlerinde bu creator/deployer cüzdanıyla ilişkili %d önceki token launchı bulundu.", previous))
	} else {
		findings = append(findings, "Koschei gözlemlerinde bu cüzdana bağlı doğrulanmış eski token launchı bulunmadı.")
	}
	if holders.CreatorIsTopHolder {
		findings = append(findings, fmt.Sprintf("Creator cüzdanı Top-20 holder sahipleri içinde #%d sırada ve yaklaşık %s arz payıyla eşleşiyor.", holders.CreatorRank, creatorIntelPercent(holders.CreatorPercentage)))
	} else if holders.Status == "verified_rpc_observation" {
		findings = append(findings, "Creator cüzdanı çözümlenen Top-20 token-account sahipleriyle doğrudan eşleşmedi.")
	}
	if earlySale > 0 {
		findings = append(findings, fmt.Sprintf("Launch gözleminden sonraki ilk 24 saat içinde %d sale-like token çıkışı görüldü.", earlySale))
	} else if saleLike > 0 {
		findings = append(findings, fmt.Sprintf("Yakın geçmişte %d swap/sale-like token çıkışı görüldü; erken satış sınıfı için launch zamanı yeterli değildi.", saleLike))
	} else {
		findings = append(findings, "İncelenen yakın işlem penceresinde creator cüzdanından sale-like token çıkışı gözlemlenmedi.")
	}
	if transferOut > 0 {
		findings = append(findings, fmt.Sprintf("Creator cüzdanından %d transfer-out işlemi görüldü; alıcı bağlantıları raporda listelendi.", transferOut))
	}
	if holderLinks > 0 {
		findings = append(findings, fmt.Sprintf("Creator’dan token alan %d cüzdan Top-20 holder sahiplerinden biriyle eşleşti.", holderLinks))
	} else if len(recipients) > 0 {
		findings = append(findings, "Creator’dan token alan cüzdanlar çözümlenen Top-20 holder sahipleriyle eşleşmedi.")
	}
	return findings
}

func creatorIntelSummary(result map[string]any) string {
	creator := creatorIntelCleanString(result["creator_wallet"])
	previous := creatorIntelInt(result["previous_launch_count"])
	early := creatorIntelInt(result["early_sale_like_transactions"])
	sale := creatorIntelInt(result["sale_like_transactions"])
	links := 0
	if rows, ok := result["holder_links"].([]map[string]any); ok {
		links = len(rows)
	}
	parts := []string{"Creator/deployer davranış katmanı yalnız kanıt fact'leri üretir; risk etkisi unified Radar ruleset v1.0 tarafından belirlenir."}
	if previous > 0 {
		parts = append(parts, fmt.Sprintf("Koschei gözlemlerinde %d önceki launch ilişkisi var.", previous))
	}
	if early > 0 {
		parts = append(parts, fmt.Sprintf("İlk 24 saatte %d sale-like çıkış görüldü.", early))
	} else if sale > 0 {
		parts = append(parts, fmt.Sprintf("Yakın geçmişte %d sale-like çıkış görüldü.", sale))
	}
	if direct, _ := result["creator_is_top_holder"].(bool); direct {
		parts = append(parts, fmt.Sprintf("Creator Top-20 içinde #%d sırada ve yaklaşık %s arz payıyla eşleşiyor.", creatorIntelInt(result["creator_holder_rank"]), creatorIntelPercent(creatorIntelFloat(result["creator_holder_percentage"]))))
	}
	if links > 0 {
		parts = append(parts, fmt.Sprintf("Creator’dan çıkan tokenların ulaştığı %d cüzdan Top-20 holder ile eşleşiyor.", links))
	}
	parts = append(parts, "Bu sonuç cüzdan davranışı ve zincir üstü ilişki analizidir; kötü niyet veya gerçek kişi kimliği iddiası değildir.")
	if creator != "" {
		return creator + " için " + strings.Join(parts, " ")
	}
	return strings.Join(parts, " ")
}

func creatorIntelPreviousLaunchCount(items []map[string]any, target string) int {
	count := 0
	for _, item := range items {
		if creatorIntelCleanString(item["target"]) != target {
			count++
		}
	}
	return count
}

func creatorIntelParsedTokenOwner(raw any) string {
	data := creatorIntelMap(raw)
	parsed := creatorIntelMap(data["parsed"])
	info := creatorIntelMap(parsed["info"])
	return creatorIntelCleanString(info["owner"])
}

func creatorIntelTokenAmount(value services.SolanaTokenAmount) float64 {
	if value.UIAmount != nil {
		return *value.UIAmount
	}
	if parsed, err := strconv.ParseFloat(strings.TrimSpace(value.UIAmountString), 64); err == nil && value.UIAmountString != "" {
		return parsed
	}
	raw, _ := strconv.ParseFloat(strings.TrimSpace(value.Amount), 64)
	if value.Decimals > 0 {
		raw /= math.Pow10(value.Decimals)
	}
	return raw
}

func creatorIntelUIAmount(value map[string]any) float64 {
	if raw := creatorIntelCleanString(value["uiAmountString"]); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
			return parsed
		}
	}
	if number, ok := value["uiAmount"].(float64); ok {
		return number
	}
	raw, _ := strconv.ParseFloat(creatorIntelCleanString(value["amount"]), 64)
	if decimals := creatorIntelInt(value["decimals"]); decimals > 0 {
		raw /= math.Pow10(decimals)
	}
	return raw
}

func creatorIntelMap(raw any) map[string]any {
	value, _ := raw.(map[string]any)
	if value == nil {
		return map[string]any{}
	}
	return value
}

func creatorIntelCleanString(raw any) string {
	value := strings.TrimSpace(fmt.Sprint(raw))
	if value == "<nil>" {
		return ""
	}
	return value
}

func creatorIntelStringSlice(raw any) []string {
	items, _ := raw.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if value := creatorIntelCleanString(item); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func creatorIntelContains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func creatorIntelInt64(raw any) int64 {
	switch value := raw.(type) {
	case int64:
		return value
	case int:
		return int64(value)
	case float64:
		return int64(value)
	case json.Number:
		parsed, _ := value.Int64()
		return parsed
	default:
		parsed, _ := strconv.ParseInt(creatorIntelCleanString(raw), 10, 64)
		return parsed
	}
}

func creatorIntelInt(raw any) int { return safeIntOrZero(creatorIntelInt64(raw)) }

func creatorIntelFloat(raw any) float64 {
	switch value := raw.(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	default:
		parsed, _ := strconv.ParseFloat(creatorIntelCleanString(raw), 64)
		return parsed
	}
}

func creatorIntelRound(value float64, decimals int) float64 {
	factor := math.Pow10(decimals)
	return math.Round(value*factor) / factor
}

func creatorIntelUnixTime(value int64) string {
	if value <= 0 {
		return ""
	}
	return time.Unix(value, 0).UTC().Format(time.RFC3339)
}

func creatorIntelPercent(value float64) string {
	return strconv.FormatFloat(creatorIntelRound(value, 4), 'f', -1, 64) + "%"
}

func creatorIntelRPCURL() string {
	return strings.TrimSpace(firstNonEmptyString(os.Getenv("SOLANA_RPC_URL"), os.Getenv("ALCHEMY_SOLANA_RPC_URL"), os.Getenv("HELIUS_SOLANA_RPC_URL"), os.Getenv("QUICKNODE_SOLANA_RPC_URL")))
}

func creatorIntelCompactError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.Join(strings.Fields(err.Error()), " ")
	if len(value) > 240 {
		value = value[:240]
	}
	return value
}
