package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"koschei/api/internal/services"
)

// OwnerActorSecurityIntelligence joins creator/deployer, holder-owner, funding
// and token-flow evidence into one wallet-level actor graph. It never turns a
// holder balance alone into an identity or fraud claim.
func (h *Handler) OwnerActorSecurityIntelligence(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(firstNonEmptyString(r.URL.Query().Get("target"), r.URL.Query().Get("mint")))
	if target == "" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "target is required")
		return
	}
	network := strings.TrimSpace(r.URL.Query().Get("network"))
	if network == "" {
		network = "solana-mainnet"
	}
	classification := classifyRadarTarget(r.Context(), target)
	if !radarTargetTokenVerdictAllowed(classification) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"ok": false, "error": "token_mint_required", "target": target,
			"target_classification": classification,
			"actor_intelligence": map[string]any{
				"available": false, "status": "token_mint_required",
				"summary": "Aktör ağı yalnız doğrulanmış token mint için üretilir.",
			},
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()
	source := h.radarDetailSourceContext(ctx, target, network)
	roles, cluster, evidenceAt := h.actorPersistedHolderEvidence(ctx, target)
	market := radarDetailMarketSnapshot(ctx, target)
	holder := services.BuildHolderIntelligence(roles, cluster, market, time.Now().UTC())

	creatorWallet := strings.TrimSpace(creatorIntelCleanString(source["creator_wallet"]))
	creator := map[string]any{
		"available": false, "status": "creator_wallet_not_observed",
		"creator_wallet": creatorWallet,
	}
	if creatorWallet != "" {
		creator = h.buildCreatorWalletIntelligence(ctx, target, network, creatorWallet, source)
	}

	actor := buildActorSecurityIntelligence(target, source, creator, holder, cluster)
	actor["holder_evidence_observed_at"] = evidenceAt
	actor["generated_at"] = time.Now().UTC().Format(time.RFC3339)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "target": target, "network": network,
		"actor_intelligence": actor,
	})
}

func (h *Handler) actorPersistedHolderEvidence(ctx context.Context, target string) (services.HolderRoleAnalysis, services.HolderClusterAnalysis, string) {
	var roles services.HolderRoleAnalysis
	var cluster services.HolderClusterAnalysis
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil || !ownerTableExists(ctx, db, "security_radar_verdicts") {
		return roles, cluster, ""
	}

	load := func(moduleID string) (map[string]json.RawMessage, time.Time, bool) {
		var raw []byte
		var observed time.Time
		err := db.QueryRowContext(ctx, `
			SELECT signals, created_at
			FROM security_radar_verdicts
			WHERE lower(target)=lower($1) AND module_id=$2 AND signed=true
			ORDER BY created_at DESC
			LIMIT 1`, target, moduleID).Scan(&raw, &observed)
		if err != nil {
			return nil, time.Time{}, false
		}
		out := map[string]json.RawMessage{}
		if json.Unmarshal(raw, &out) != nil {
			return nil, time.Time{}, false
		}
		return out, observed.UTC(), true
	}

	var observed time.Time
	if signals, at, ok := load("funding_cluster_detector"); ok {
		observed = at
		if raw := signals["holder_role_analysis"]; len(raw) > 0 {
			_ = json.Unmarshal(raw, &roles)
		}
		if raw := signals["holder_cluster_analysis"]; len(raw) > 0 {
			_ = json.Unmarshal(raw, &cluster)
		}
	}
	if !roles.Available {
		if signals, at, ok := load("holder_concentration"); ok {
			if observed.IsZero() || at.After(observed) {
				observed = at
			}
			if raw := signals["holder_role_analysis"]; len(raw) > 0 {
				_ = json.Unmarshal(raw, &roles)
			}
		}
	}
	if observed.IsZero() {
		return roles, cluster, ""
	}
	return roles, cluster, observed.Format(time.RFC3339)
}

type actorGraphBuilder struct {
	nodes    []map[string]any
	links    []map[string]any
	nodeSeen map[string]bool
	linkSeen map[string]bool
}

func newActorGraphBuilder() *actorGraphBuilder {
	return &actorGraphBuilder{nodes: []map[string]any{}, links: []map[string]any{}, nodeSeen: map[string]bool{}, linkSeen: map[string]bool{}}
}

func (b *actorGraphBuilder) addNode(id, kind, role, confidence string, extra map[string]any) {
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	key := strings.ToLower(kind + "|" + id)
	if b.nodeSeen[key] {
		return
	}
	b.nodeSeen[key] = true
	node := map[string]any{"id": id, "kind": kind, "role": role, "confidence": confidence}
	for k, v := range extra {
		node[k] = v
	}
	b.nodes = append(b.nodes, node)
}

func (b *actorGraphBuilder) addLink(from, to, relation string, verified bool, extra map[string]any) {
	from, to = strings.TrimSpace(from), strings.TrimSpace(to)
	if from == "" || to == "" || relation == "" {
		return
	}
	signature := strings.TrimSpace(fmt.Sprint(extra["signature"]))
	key := strings.ToLower(from + "|" + to + "|" + relation + "|" + signature)
	if b.linkSeen[key] {
		return
	}
	b.linkSeen[key] = true
	link := map[string]any{"from": from, "to": to, "relation": relation, "verified": verified}
	for k, v := range extra {
		if fmt.Sprint(v) != "" && fmt.Sprint(v) != "<nil>" {
			link[k] = v
		}
	}
	b.links = append(b.links, link)
}

func buildActorSecurityIntelligence(target string, source, creator map[string]any, holder services.HolderIntelligence, cluster services.HolderClusterAnalysis) map[string]any {
	g := newActorGraphBuilder()
	g.addNode(target, "token", "investigated_token", "verified", nil)

	creatorWallet := strings.TrimSpace(firstNonEmptyString(creatorIntelCleanString(creator["creator_wallet"]), creatorIntelCleanString(source["creator_wallet"])))
	creatorRelationVerified, _ := source["creator_relation_verified"].(bool)
	if creatorWallet != "" {
		g.addNode(creatorWallet, "wallet", "creator_deployer", actorConfidence(creatorRelationVerified), map[string]any{
			"source": creatorIntelCleanString(source["source"]),
		})
		g.addLink(creatorWallet, target, "created_or_deployed", creatorRelationVerified, map[string]any{
			"signature":   creatorIntelCleanString(source["signature"]),
			"observed_at": creatorIntelCleanString(source["observed_at"]),
			"evidence":    []string{"Launch source reported this wallet as the creator/deployer relation."},
		})
	}

	for _, row := range holder.Rows {
		id := strings.TrimSpace(row.OwnerWallet)
		kind := "wallet"
		if id == "" && len(row.TokenAccounts) > 0 {
			id = row.TokenAccounts[0]
			kind = "unresolved_control_surface"
		}
		if row.ExcludedFromHolderRisk {
			kind = "protocol_inventory"
		}
		confidence := strings.TrimSpace(row.RoleConfidence)
		if confidence == "" {
			confidence = "unknown"
		}
		g.addNode(id, kind, row.Role, confidence, map[string]any{
			"holder_rank": row.Rank, "raw_percentage": row.RawPercentage,
			"circulating_percentage": row.CirculatingPercentage,
			"token_account_count":    row.TokenAccountCount,
		})
		g.addLink(id, target, "controls_token_balance", row.OwnerResolved || row.ExcludedFromHolderRisk, map[string]any{
			"amount_token": row.Balance, "raw_percentage": row.RawPercentage,
			"circulating_percentage": row.CirculatingPercentage,
			"evidence":               row.Evidence,
		})
	}

	previousLaunches := actorMapRows(creator["observed_launches"])
	for _, launch := range previousLaunches {
		mint := strings.TrimSpace(creatorIntelCleanString(launch["target"]))
		if creatorWallet == "" || mint == "" {
			continue
		}
		g.addNode(mint, "token", "creator_observed_launch", "observed", nil)
		g.addLink(creatorWallet, mint, "observed_launch_relation", true, map[string]any{
			"signature":   creatorIntelCleanString(launch["signature"]),
			"observed_at": fmt.Sprint(launch["observed_at"]),
			"source":      creatorIntelCleanString(launch["source"]),
		})
	}

	for _, row := range actorMapRows(creator["funding_wallets"]) {
		wallet := strings.TrimSpace(creatorIntelCleanString(row["wallet"]))
		if creatorWallet == "" || wallet == "" {
			continue
		}
		g.addNode(wallet, "wallet", "creator_funder", "observed", nil)
		g.addLink(wallet, creatorWallet, "funded_creator", true, map[string]any{
			"amount_sol":        creatorIntelFloat(row["amount"]),
			"transactions":      creatorIntelInt(row["transactions"]),
			"first_observed_at": creatorIntelCleanString(row["first_observed_at"]),
			"last_observed_at":  creatorIntelCleanString(row["last_observed_at"]),
		})
	}

	creatorHolderLinks := 0
	for _, row := range actorMapRows(creator["recipient_wallets"]) {
		wallet := strings.TrimSpace(creatorIntelCleanString(row["wallet"]))
		if creatorWallet == "" || wallet == "" {
			continue
		}
		matched, _ := row["matches_top_holder"].(bool)
		role := "creator_token_recipient"
		if matched {
			role = "creator_linked_top_holder"
			creatorHolderLinks++
		}
		g.addNode(wallet, "wallet", role, "observed", map[string]any{
			"holder_rank": row["holder_rank"], "holder_percentage": row["holder_percentage"],
		})
		g.addLink(creatorWallet, wallet, "creator_token_outflow_recipient", true, map[string]any{
			"amount_token":       creatorIntelFloat(row["amount"]),
			"transactions":       creatorIntelInt(row["transactions"]),
			"matches_top_holder": matched,
			"first_observed_at":  creatorIntelCleanString(row["first_observed_at"]),
			"last_observed_at":   creatorIntelCleanString(row["last_observed_at"]),
		})
	}

	for _, wallet := range cluster.Wallets {
		if strings.TrimSpace(wallet.Wallet) == "" {
			continue
		}
		g.addNode(wallet.Wallet, "wallet", "analyzed_top_holder", "observed", map[string]any{
			"holder_rank": wallet.Rank, "holder_percentage": wallet.HolderPercentage,
			"signatures_observed": wallet.SignaturesObserved,
			"parsed_transactions": wallet.ParsedTransactions,
		})
		if strings.TrimSpace(wallet.FundingSource) != "" {
			g.addNode(wallet.FundingSource, "wallet", "holder_funder", "observed", nil)
			g.addLink(wallet.FundingSource, wallet.Wallet, "funded_top_holder", true, map[string]any{
				"amount_sol":  wallet.FundingAmountSOL,
				"observed_at": wallet.FundingObservedAt,
				"evidence":    wallet.Evidence,
			})
		}
	}

	for _, observation := range cluster.Flow.Observations {
		g.addNode(observation.SourceWallet, "wallet", "top_holder", "observed", nil)
		g.addNode(observation.Destination, actorDestinationKind(observation), actorDestinationRole(observation), "observed", nil)
		g.addLink(observation.SourceWallet, observation.Destination, observation.Kind, true, map[string]any{
			"amount_token": observation.Amount, "slot": observation.Slot,
			"signature": observation.Signature, "program_ids": observation.ProgramIDs,
			"evidence": observation.Evidence,
		})
	}

	sort.SliceStable(g.nodes, func(i, j int) bool { return fmt.Sprint(g.nodes[i]["id"]) < fmt.Sprint(g.nodes[j]["id"]) })
	crossLinks := actorCrossLinkCount(g.links)
	creatorChecked := creatorIntelInt(creator["recent_transactions_checked"])
	coverage := map[string]any{
		"top_holder_balances":          len(holder.Rows),
		"holder_wallets_requested":     cluster.WalletsRequested,
		"holder_wallets_analyzed":      cluster.WalletsAnalyzed,
		"creator_signatures_seen":      creatorIntelInt(creator["recent_signatures_seen"]),
		"creator_transactions_checked": creatorChecked,
		"creator_relation_verified":    creatorRelationVerified,
		"cross_actor_links":            crossLinks,
	}

	findings := actorSecurityFindings(creatorWallet, creator, holder, cluster, creatorHolderLinks, crossLinks)
	status, confidence := actorSecurityStatus(creatorWallet, creatorRelationVerified, creatorChecked, cluster.WalletsAnalyzed, crossLinks)
	return map[string]any{
		"available": creatorWallet != "" || cluster.WalletsAnalyzed > 0,
		"status":    status, "confidence": confidence,
		"identity_scope":                  "wallet_level_control_network_only",
		"creator_wallet":                  creatorWallet,
		"creator_relation_verified":       creatorRelationVerified,
		"previous_launch_count":           creatorIntelInt(creator["previous_launch_count"]),
		"creator_is_top_holder":           creator["creator_is_top_holder"],
		"creator_holder_percentage":       creator["creator_holder_percentage"],
		"sale_like_transactions":          creatorIntelInt(creator["sale_like_transactions"]),
		"early_sale_like_transactions":    creatorIntelInt(creator["early_sale_like_transactions"]),
		"creator_linked_top_holder_count": creatorHolderLinks,
		"shared_funding_group_count":      cluster.SharedFundingGroupCount,
		"synchronized_wallet_count":       cluster.SynchronizedWalletCount,
		"common_exit_group_count":         cluster.Flow.CommonExitGroupCount,
		"internal_transfer_count":         cluster.Flow.InternalTransferCount,
		"coverage":                        coverage,
		"nodes":                           g.nodes, "links": g.links,
		"findings":           findings,
		"recommended_action": actorRecommendedAction(status, crossLinks, creatorWallet, cluster.WalletsAnalyzed),
		"limitations": []string{
			"Cüzdan bağlantıları gerçek dünya kimliği veya suç isnadı değildir; yalnız zincir üstü kontrol ve fon akışı kanıtıdır.",
			"Holder davranışı yalnız incelenen imza ve parsed transaction penceresiyle sınırlıdır.",
			"Borsa, market maker, servis ve havuz adresleri eksik etiketlenmiş olabilir.",
		},
	}
}

func actorSecurityStatus(creator string, creatorVerified bool, creatorChecked, holderAnalyzed, crossLinks int) (string, string) {
	switch {
	case creator == "" && holderAnalyzed == 0:
		return "actor_evidence_unavailable", "none"
	case crossLinks > 0 && creatorVerified && creatorChecked > 0 && holderAnalyzed >= 3:
		return "verified_linked_actor_network", "high"
	case creatorVerified && creatorChecked > 0 && holderAnalyzed >= 3:
		return "verified_actor_observation_no_cross_link", "medium"
	case creator != "" || holderAnalyzed > 0:
		return "partial_actor_observation", "low"
	default:
		return "actor_evidence_unavailable", "none"
	}
}

func actorSecurityFindings(creator string, intel map[string]any, holder services.HolderIntelligence, cluster services.HolderClusterAnalysis, creatorHolderLinks, crossLinks int) []string {
	out := []string{}
	if creator == "" {
		out = append(out, "Creator/deployer kök cüzdanı doğrulanamadı; aktör ağı tamamlanmış sayılmaz.")
	} else {
		out = append(out, fmt.Sprintf("Creator/deployer kök cüzdanı %s olarak gözlendi.", shortHolderIntelligence(creator)))
	}
	if count := creatorIntelInt(intel["previous_launch_count"]); count > 0 {
		out = append(out, fmt.Sprintf("Aynı creator cüzdanıyla ilişkili %d önceki Koschei launch kaydı bulundu.", count))
	}
	if value, _ := intel["creator_is_top_holder"].(bool); value {
		out = append(out, fmt.Sprintf("Creator cüzdanı Top holder listesinde; gözlenen payı yaklaşık %.4f%%.", creatorIntelFloat(intel["creator_holder_percentage"])))
	}
	if early := creatorIntelInt(intel["early_sale_like_transactions"]); early > 0 {
		out = append(out, fmt.Sprintf("Creator için launch sonrası ilk 24 saat penceresinde %d sale-like token çıkışı gözlendi.", early))
	}
	if creatorHolderLinks > 0 {
		out = append(out, fmt.Sprintf("Creator token çıkışı %d Top-holder cüzdanıyla eşleşti.", creatorHolderLinks))
	}
	if cluster.SharedFundingGroupCount > 0 {
		out = append(out, fmt.Sprintf("Top holderlar arasında %d ortak funding kaynağı grubu gözlendi.", cluster.SharedFundingGroupCount))
	}
	if cluster.Flow.CommonExitGroupCount > 0 {
		out = append(out, fmt.Sprintf("Top holderlar arasında %d ortak token çıkış recipient grubu gözlendi.", cluster.Flow.CommonExitGroupCount))
	}
	if crossLinks == 0 {
		out = append(out, "İncelenen sınırlı pencerede creator, funder ve Top holderlar arasında güçlü çapraz bağlantı doğrulanmadı.")
	}
	out = append(out, fmt.Sprintf("Sahiplik kapsamı %d kontrol yüzeyi; davranış kapsamı %d/%d holder wallet.", len(holder.Rows), cluster.WalletsAnalyzed, cluster.WalletsRequested))
	return out
}

func actorRecommendedAction(status string, crossLinks int, creator string, holderAnalyzed int) string {
	switch {
	case creator == "":
		return "Creator/deployer kök cüzdanını doğrula; doğrulanmadan güvenlik hükmü üretme."
	case crossLinks > 0:
		return "Bağlantılı creator/funder/holder akışlarının imzalarını aç ve para-token çıkış zincirini derinleştir."
	case holderAnalyzed < 3:
		return "Top holder davranış kapsamını genişlet; mevcut veri aktör ilişkisini dışlamak için yetersiz."
	case status == "verified_actor_observation_no_cross_link":
		return "Sınırlı pencerede güçlü bağlantı yok; önceki launch ve tam geçmiş doğrulanmadan güvenli hüküm verme."
	default:
		return "Kanıt kapsamını genişlet ve yalnız doğrulanmış aktör bağlantılarını müşteriye göster."
	}
}

func actorMapRows(value any) []map[string]any {
	switch rows := value.(type) {
	case []map[string]any:
		return rows
	case []any:
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			if item, ok := row.(map[string]any); ok {
				out = append(out, item)
			}
		}
		return out
	default:
		return []map[string]any{}
	}
}

func actorCrossLinkCount(links []map[string]any) int {
	count := 0
	for _, link := range links {
		relation := strings.TrimSpace(fmt.Sprint(link["relation"]))
		if relation != "controls_token_balance" && relation != "created_or_deployed" && relation != "observed_launch_relation" {
			count++
		}
	}
	return count
}

func actorConfidence(verified bool) string {
	if verified {
		return "verified"
	}
	return "observed"
}

func actorDestinationKind(observation services.HolderClusterFlowObservation) string {
	if observation.Kind == "dex_program_exit_context" {
		return "program"
	}
	return "wallet"
}

func actorDestinationRole(observation services.HolderClusterFlowObservation) string {
	switch observation.Kind {
	case "holder_to_holder":
		return "linked_top_holder"
	case "dex_program_exit_context":
		return "dex_or_pool_route"
	default:
		return "token_exit_recipient"
	}
}
