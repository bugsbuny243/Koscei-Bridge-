package services

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	piFundingCandidateLimit   = 8
	piFundingOperationLimit   = 100
	piFundingEvidenceSource   = "pi_horizon_account_operations"
	piFundingCreationRelation = "account_creation"
	piFundingPaymentRelation  = "earliest_native_inbound"
)

type PiFundingOriginRow struct {
	Wallet             string `json:"wallet"`
	SourceAccount      string `json:"source_account"`
	Relation           string `json:"relation"`
	OperationID        string `json:"operation_id"`
	TransactionHash    string `json:"transaction_hash"`
	Amount             string `json:"amount,omitempty"`
	Timestamp          string `json:"timestamp"`
	HistoryComplete    bool   `json:"history_complete"`
	VerificationStatus string `json:"verification_status"`
	EvidenceSource     string `json:"evidence_source"`
}

type PiFundingSharedSourceGroup struct {
	SourceAccount string   `json:"source_account"`
	WalletCount   int      `json:"wallet_count"`
	Wallets       []string `json:"wallets"`
}

type PiFundingClusterObservation struct {
	Status                   string                       `json:"status"`
	EvidenceStatus           string                       `json:"evidence_status"`
	Source                   string                       `json:"source"`
	Asset                    string                       `json:"asset"`
	HolderCandidatesObserved int                          `json:"holder_candidates_observed"`
	HolderCandidatesQueried  int                          `json:"holder_candidates_queried"`
	FundingRowsObserved      int                          `json:"funding_rows_observed"`
	CandidateSetComplete     bool                         `json:"candidate_set_complete"`
	HistoryWindowComplete    bool                         `json:"history_window_complete"`
	SharedSourceGroupCount   int                          `json:"shared_source_group_count"`
	LargestSharedSourceGroup int                          `json:"largest_shared_source_group"`
	SharedSources            []PiFundingSharedSourceGroup `json:"shared_sources"`
	Rows                     []PiFundingOriginRow         `json:"rows"`
	Limitations              []string                     `json:"limitations,omitempty"`
	GeneratedAt              string                       `json:"generated_at"`
}

type piFundingHorizonOperation struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	TransactionHash string `json:"transaction_hash"`
	SourceAccount   string `json:"source_account"`
	CreatedAt       string `json:"created_at"`
	Funder          string `json:"funder"`
	Account         string `json:"account"`
	StartingBalance string `json:"starting_balance"`
	From            string `json:"from"`
	To              string `json:"to"`
	AssetType       string `json:"asset_type"`
	Amount          string `json:"amount"`
}

type piFundingHorizonOperationPage struct {
	Embedded struct {
		Records []piFundingHorizonOperation `json:"records"`
	} `json:"_embedded"`
}

// enrichPiFundingClusterEvidence collects the earliest observable account
// creation or native inbound funding relation for a bounded set of the largest
// Pi trustline holders. A shared funder is evidence of a shared funding source,
// never proof of common ownership or a real-world identity.
func enrichPiFundingClusterEvidence(ctx context.Context, analysis ArvisAnalysis, target PiRadarTarget) ArvisAnalysis {
	if target.Kind != piRadarTargetKindAsset {
		return analysis
	}
	observation := collectPiFundingClusterObservation(ctx, target, piHolderCandidatesFromAnalysis(analysis))
	if analysis.Bundle.Metadata == nil {
		analysis.Bundle.Metadata = map[string]any{}
	}
	analysis.Bundle.Metadata["pi_funding_cluster"] = observation
	analysis.Bundle.Metadata["pi_funding_cluster_source"] = piFundingEvidenceSource
	analysis.Bundle.Metadata["pi_funding_cluster_identity_claim"] = false
	for index := range analysis.Arms {
		if analysis.Arms[index].ModuleID == ModuleFundingClusterDetector {
			analysis.Arms[index] = applyPiFundingClusterToArm(analysis.Arms[index], observation)
			break
		}
	}
	analysis.Graph = applyPiFundingClusterToGraph(analysis.Graph, observation)
	analysis.Bundle.Metadata["arvis_arms"] = analysis.Arms
	analysis.Bundle.Metadata["intelligence_graph"] = analysis.Graph
	return analysis
}

func piHolderCandidatesFromAnalysis(analysis ArvisAnalysis) []piHolderObservation {
	for _, arm := range analysis.Arms {
		if arm.ModuleID != ModuleHolderConcentration || arm.Signals == nil {
			continue
		}
		if holders, ok := arm.Signals["pi_holder_observations"].([]piHolderObservation); ok {
			return append([]piHolderObservation{}, holders...)
		}
	}
	return nil
}

func collectPiFundingClusterObservation(ctx context.Context, target PiRadarTarget, holders []piHolderObservation) PiFundingClusterObservation {
	asset := target.AssetCode + ":" + target.Issuer
	out := PiFundingClusterObservation{
		Status:                "not_observed",
		EvidenceStatus:        "insufficient_evidence",
		Source:                piFundingEvidenceSource,
		Asset:                 asset,
		CandidateSetComplete:  true,
		HistoryWindowComplete: true,
		SharedSources:         []PiFundingSharedSourceGroup{},
		Rows:                  []PiFundingOriginRow{},
		Limitations:           []string{},
		GeneratedAt:           time.Now().UTC().Format(time.RFC3339),
	}
	candidates := selectPiFundingCandidates(holders)
	out.HolderCandidatesObserved = len(holders)
	if len(candidates) == 0 {
		out.Status = "no_holder_candidates"
		out.Limitations = append(out.Limitations, "No positive-balance Pi holder accounts were available for funding provenance collection.")
		return out
	}
	if len(holders) > len(candidates) {
		out.CandidateSetComplete = false
		out.Limitations = append(out.Limitations, fmt.Sprintf("Funding provenance was bounded to the %d largest observed holder accounts.", len(candidates)))
	}
	base, err := piHorizonBaseURL()
	if err != nil {
		out.Status = "provider_unavailable"
		out.HistoryWindowComplete = false
		out.Limitations = append(out.Limitations, compactPiHorizonError(err))
		return out
	}
	client := &http.Client{Timeout: piHorizonRequestTimeout}
	for _, candidate := range candidates {
		row, complete, err := collectPiWalletFundingOrigin(ctx, client, base, candidate.Account)
		out.HolderCandidatesQueried++
		if err != nil {
			out.HistoryWindowComplete = false
			out.Limitations = append(out.Limitations, "Funding provenance for "+candidate.Account+" could not be collected: "+compactPiHorizonError(err))
			continue
		}
		if !complete {
			out.HistoryWindowComplete = false
		}
		if row != nil {
			out.Rows = append(out.Rows, *row)
		}
	}
	out.FundingRowsObserved = len(out.Rows)
	out.SharedSources, out.LargestSharedSourceGroup = piFundingSharedSourceGroups(out.Rows)
	out.SharedSourceGroupCount = len(out.SharedSources)

	switch {
	case out.FundingRowsObserved >= 3:
		out.Status = "observed"
		out.EvidenceStatus = "observed"
	case out.FundingRowsObserved > 0:
		out.Status = "partial_observation"
		out.EvidenceStatus = "partial_observation"
	default:
		out.Status = "no_funding_origin_observed"
		out.EvidenceStatus = "insufficient_evidence"
	}
	if !out.CandidateSetComplete || !out.HistoryWindowComplete {
		out.Limitations = append(out.Limitations, "Funding provenance is bounded evidence and must not be represented as complete account history.")
	}
	if out.SharedSourceGroupCount == 0 {
		out.Limitations = append(out.Limitations, "No repeated funding source was observed in this bounded holder set; this is not proof that the holders are unrelated.")
	}
	return out
}

func selectPiFundingCandidates(holders []piHolderObservation) []piHolderObservation {
	values := append([]piHolderObservation{}, holders...)
	sort.SliceStable(values, func(i, j int) bool {
		if values[i].Balance == values[j].Balance {
			return values[i].Account < values[j].Account
		}
		return values[i].Balance > values[j].Balance
	})
	out := make([]piHolderObservation, 0, piFundingCandidateLimit)
	seen := map[string]bool{}
	for _, holder := range values {
		account := strings.TrimSpace(holder.Account)
		if account == "" || holder.Balance <= 0 || seen[account] {
			continue
		}
		seen[account] = true
		holder.Account = account
		out = append(out, holder)
		if len(out) >= piFundingCandidateLimit {
			break
		}
	}
	return out
}

func collectPiWalletFundingOrigin(ctx context.Context, client *http.Client, base *url.URL, wallet string) (*PiFundingOriginRow, bool, error) {
	wallet = strings.TrimSpace(wallet)
	if wallet == "" {
		return nil, false, fmt.Errorf("wallet is empty")
	}
	query := url.Values{
		"order": []string{"asc"},
		"limit": []string{strconv.Itoa(piFundingOperationLimit)},
	}
	var page piFundingHorizonOperationPage
	path := "/accounts/" + url.PathEscape(wallet) + "/operations"
	if err := piHorizonGetJSON(ctx, client, base, path, query, &page); err != nil {
		return nil, false, err
	}
	complete := len(page.Embedded.Records) < piFundingOperationLimit
	for _, operation := range page.Embedded.Records {
		row, ok := piFundingOriginRow(wallet, operation, complete)
		if ok {
			return &row, complete, nil
		}
	}
	return nil, complete, nil
}

func piFundingOriginRow(wallet string, operation piFundingHorizonOperation, historyComplete bool) (PiFundingOriginRow, bool) {
	wallet = strings.TrimSpace(wallet)
	operationType := strings.ToLower(strings.TrimSpace(operation.Type))
	row := PiFundingOriginRow{
		Wallet:             wallet,
		OperationID:        strings.TrimSpace(operation.ID),
		TransactionHash:    strings.TrimSpace(operation.TransactionHash),
		Timestamp:          strings.TrimSpace(operation.CreatedAt),
		HistoryComplete:    historyComplete,
		VerificationStatus: "verified_horizon_operation",
		EvidenceSource:     piFundingEvidenceSource,
	}
	switch operationType {
	case "create_account":
		if strings.TrimSpace(operation.Account) != wallet {
			return PiFundingOriginRow{}, false
		}
		row.SourceAccount = strings.TrimSpace(operation.Funder)
		if row.SourceAccount == "" {
			row.SourceAccount = strings.TrimSpace(operation.SourceAccount)
		}
		row.Relation = piFundingCreationRelation
		row.Amount = strings.TrimSpace(operation.StartingBalance)
	case "payment":
		if strings.TrimSpace(operation.To) != wallet || !strings.EqualFold(strings.TrimSpace(operation.AssetType), "native") {
			return PiFundingOriginRow{}, false
		}
		row.SourceAccount = strings.TrimSpace(operation.From)
		if row.SourceAccount == "" {
			row.SourceAccount = strings.TrimSpace(operation.SourceAccount)
		}
		row.Relation = piFundingPaymentRelation
		row.Amount = strings.TrimSpace(operation.Amount)
	default:
		return PiFundingOriginRow{}, false
	}
	if row.SourceAccount == "" || row.SourceAccount == wallet || row.TransactionHash == "" {
		return PiFundingOriginRow{}, false
	}
	return row, true
}

func piFundingSharedSourceGroups(rows []PiFundingOriginRow) ([]PiFundingSharedSourceGroup, int) {
	grouped := map[string]map[string]bool{}
	for _, row := range rows {
		source := strings.TrimSpace(row.SourceAccount)
		wallet := strings.TrimSpace(row.Wallet)
		if source == "" || wallet == "" {
			continue
		}
		if grouped[source] == nil {
			grouped[source] = map[string]bool{}
		}
		grouped[source][wallet] = true
	}
	groups := make([]PiFundingSharedSourceGroup, 0)
	largest := 0
	for source, walletSet := range grouped {
		if len(walletSet) < 2 {
			continue
		}
		wallets := make([]string, 0, len(walletSet))
		for wallet := range walletSet {
			wallets = append(wallets, wallet)
		}
		sort.Strings(wallets)
		group := PiFundingSharedSourceGroup{SourceAccount: source, WalletCount: len(wallets), Wallets: wallets}
		groups = append(groups, group)
		if group.WalletCount > largest {
			largest = group.WalletCount
		}
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].WalletCount == groups[j].WalletCount {
			return groups[i].SourceAccount < groups[j].SourceAccount
		}
		return groups[i].WalletCount > groups[j].WalletCount
	})
	return groups, largest
}

func applyPiFundingClusterToArm(arm SecurityRadarVerdict, observation PiFundingClusterObservation) SecurityRadarVerdict {
	if arm.Signals == nil {
		arm.Signals = map[string]any{}
	}
	arm.Signals["pi_funding_cluster"] = observation
	arm.Signals["funding_rows_observed"] = observation.FundingRowsObserved
	arm.Signals["shared_funding_group_count"] = observation.SharedSourceGroupCount
	arm.Signals["largest_shared_funding_group"] = observation.LargestSharedSourceGroup
	arm.Signals["funding_history_complete"] = observation.HistoryWindowComplete
	arm.Signals["funding_candidate_set_complete"] = observation.CandidateSetComplete
	arm.Signals["same_controller_claim"] = false
	arm.Signals["identity_claim"] = false
	arm.Signals["grade_effect"] = "none_at_arm_layer"
	arm.Signals["numeric_score_disabled"] = true

	if observation.FundingRowsObserved >= 3 {
		arm.Signals["arm_evidence_available"] = true
		arm.Signals["evidence_status"] = "observed"
		arm.RiskLevel = "evidence_only"
		arm.Verdict = "Pi holder funding evidence observed; no Pi risk grade is enabled."
		arm.Recommendation = "review_pi_evidence"
		arm.Evidence = append(arm.Evidence, fmt.Sprintf("Funding provenance was observed for %d bounded Pi holder account(s).", observation.FundingRowsObserved))
		if observation.SharedSourceGroupCount > 0 {
			arm.Evidence = append(arm.Evidence, fmt.Sprintf("Observed %d repeated funding source group(s); largest group funds %d holder account(s).", observation.SharedSourceGroupCount, observation.LargestSharedSourceGroup))
		} else {
			arm.Evidence = append(arm.Evidence, "No repeated funding source was observed in the bounded holder set; absence is not evidence that holders are unrelated.")
		}
		for index, row := range observation.Rows {
			if index >= 8 {
				arm.Evidence = append(arm.Evidence, fmt.Sprintf("%d additional funding row(s) remain in structured evidence.", len(observation.Rows)-index))
				break
			}
			arm.Evidence = append(arm.Evidence, fmt.Sprintf("holder=%s source=%s relation=%s tx=%s amount=%s timestamp=%s.", row.Wallet, row.SourceAccount, row.Relation, row.TransactionHash, row.Amount, row.Timestamp))
		}
	} else if observation.FundingRowsObserved > 0 {
		arm.Signals["evidence_status"] = "partial_observation"
		arm.Evidence = append(arm.Evidence, fmt.Sprintf("Only %d holder funding origin row(s) were observed; at least three are required before the Funding Cluster arm is considered evidence-ready.", observation.FundingRowsObserved))
	} else {
		arm.Evidence = append(arm.Evidence, "No holder funding origin row was verified in the bounded Pi account-operation window.")
	}
	for _, limitation := range observation.Limitations {
		arm.Evidence = append(arm.Evidence, "Limitation: "+limitation)
	}
	arm.Evidence = append(arm.Evidence, "A shared on-chain funding source is not proof of common control, legal identity or wrongdoing.")
	return arm
}

func applyPiFundingClusterToGraph(graph SecurityRadarVerdict, observation PiFundingClusterObservation) SecurityRadarVerdict {
	if graph.Signals == nil || len(observation.Rows) == 0 {
		return graph
	}
	nodes := piGraphMaps(graph.Signals["nodes"])
	edges := piGraphMaps(graph.Signals["edges"])
	for _, row := range observation.Rows {
		nodes = appendPiGraphNode(nodes, map[string]any{"id": row.SourceAccount, "kind": "funding_source", "chain": "pi", "identity_claim": false})
		nodes = appendPiGraphNode(nodes, map[string]any{"id": row.Wallet, "kind": "holder_account", "chain": "pi"})
		relation := "earliest_native_inbound_observed"
		if row.Relation == piFundingCreationRelation {
			relation = "funded_account_creation"
		}
		edges = appendPiGraphEdge(edges, map[string]any{
			"source":              row.SourceAccount,
			"destination":         row.Wallet,
			"relation":            relation,
			"transaction_hash":    row.TransactionHash,
			"operation_id":        row.OperationID,
			"amount":              row.Amount,
			"timestamp":           row.Timestamp,
			"verification_status": row.VerificationStatus,
			"identity_claim":      false,
		})
	}
	graph.Signals["nodes"] = nodes
	graph.Signals["edges"] = edges
	graph.Signals["pi_funding_cluster"] = observation
	graph.Evidence = append(graph.Evidence, "Pi holder funding-source relations were added from verified Horizon account operations; shared funding is not treated as shared identity.")
	return graph
}

func appendPiGraphNode(nodes []map[string]any, candidate map[string]any) []map[string]any {
	id := strings.TrimSpace(fmt.Sprint(candidate["id"]))
	kind := strings.TrimSpace(fmt.Sprint(candidate["kind"]))
	for _, node := range nodes {
		if strings.TrimSpace(fmt.Sprint(node["id"])) == id && strings.TrimSpace(fmt.Sprint(node["kind"])) == kind {
			return nodes
		}
	}
	return append(nodes, candidate)
}

func appendPiGraphEdge(edges []map[string]any, candidate map[string]any) []map[string]any {
	source := strings.TrimSpace(fmt.Sprint(candidate["source"]))
	destination := strings.TrimSpace(fmt.Sprint(candidate["destination"]))
	relation := strings.TrimSpace(fmt.Sprint(candidate["relation"]))
	tx := strings.TrimSpace(fmt.Sprint(candidate["transaction_hash"]))
	for _, edge := range edges {
		if strings.TrimSpace(fmt.Sprint(edge["source"])) == source && strings.TrimSpace(fmt.Sprint(edge["destination"])) == destination && strings.TrimSpace(fmt.Sprint(edge["relation"])) == relation && strings.TrimSpace(fmt.Sprint(edge["transaction_hash"])) == tx {
			return edges
		}
	}
	return append(edges, candidate)
}

func refreshPiAnalysisEvidenceMetadata(analysis ArvisAnalysis) ArvisAnalysis {
	if analysis.Bundle.Metadata == nil {
		analysis.Bundle.Metadata = map[string]any{}
	}
	observed := piObservedEvidenceArmCount(analysis.Arms)
	analysis.Bundle.Metadata["observed_arm_count"] = observed
	analysis.Bundle.Metadata["arvis_arms"] = analysis.Arms
	analysis.Bundle.Metadata["intelligence_graph"] = analysis.Graph
	if observed > 0 {
		analysis.Bundle.CustomerSummary = fmt.Sprintf("ARVIS collected Pi Testnet evidence in %d of 14 arms. Pi grading remains disabled until a Pi-specific deterministic ruleset passes its regression corpus.", observed)
	}
	return analysis
}
