package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const ActorAcceptanceContractVersion = "koschei-actor-acceptance-v1"

const (
	ActorAcceptancePass            = "pass"
	ActorAcceptanceFail            = "fail"
	ActorAcceptanceNotInvestigated = "not_investigated"
)

type ActorAcceptanceInput struct {
	Wallet        string
	Network       string
	TargetKind    string
	Dossier       ActorDefenseDossier
	FundingOrigin ActorFundingOrigin
	Verdict       ActorDefenseRuleVerdict
}

type ActorAcceptanceEvidenceLine struct {
	Kind               string    `json:"kind"`
	EvidenceKey        string    `json:"evidence_key"`
	Relation           string    `json:"relation"`
	Signature          string    `json:"signature,omitempty"`
	Slot               int64     `json:"slot,omitempty"`
	Timestamp          time.Time `json:"timestamp,omitempty"`
	SourceWallet       string    `json:"source_wallet"`
	DestinationWallet  string    `json:"destination_wallet"`
	Amount             string    `json:"amount"`
	Program            string    `json:"program"`
	VerificationStatus string    `json:"verification_status"`
	TokenMint          string    `json:"token_mint,omitempty"`
	EvidenceSource     string    `json:"evidence_source,omitempty"`
}

type ActorAcceptanceItem struct {
	ID            string                        `json:"id"`
	Question      string                        `json:"question"`
	Status        string                        `json:"status"`
	EvidenceState string                        `json:"evidence_state"`
	Summary       string                        `json:"summary"`
	Evidence      []ActorAcceptanceEvidenceLine `json:"evidence"`
	Limitations   []string                      `json:"limitations"`
}

type ActorAcceptanceVerdict struct {
	Grade          string                `json:"grade"`
	Verdict        string                `json:"verdict"`
	RulesetVersion string                `json:"ruleset_version"`
	TriggeredRules []ActorDefenseRuleHit `json:"triggered_rules"`
	WatchFlags     []ActorDefenseRuleHit `json:"watch_flags"`
	DecisionPath   []string              `json:"decision_path"`
	Signed         bool                  `json:"signed"`
	Signature      string                `json:"signature,omitempty"`
}

type ActorAcceptanceResult struct {
	ContractVersion      string                 `json:"contract_version"`
	ActorRulesetVersion  string                 `json:"actor_ruleset_version"`
	Wallet               string                 `json:"wallet"`
	Network              string                 `json:"network"`
	Status               string                 `json:"status"`
	PassCount            int                    `json:"pass_count"`
	FailCount            int                    `json:"fail_count"`
	NotInvestigatedCount int                    `json:"not_investigated_count"`
	Items                []ActorAcceptanceItem  `json:"items"`
	Verdict              ActorAcceptanceVerdict `json:"verdict"`
	AcceptanceHash       string                 `json:"acceptance_hash"`
}

func EvaluateActorAcceptance(input ActorAcceptanceInput) ActorAcceptanceResult {
	wallet := strings.TrimSpace(input.Wallet)
	network := normalizeRadarNetwork(input.Network)
	verdict := actorAcceptanceVerdict(input.Verdict)
	items := []ActorAcceptanceItem{
		actorAcceptanceControlItem("AC-01", "Wallet can be submitted to the owner investigation surface", wallet != "", "owner_wallet_input", wallet, "Owner wallet input is present and bounded to one actor target."),
		actorAcceptanceControlItem("AC-02", "Target is classified as a wallet", strings.EqualFold(strings.TrimSpace(input.TargetKind), "wallet"), "wallet_target_classification", wallet, "Target classification resolved the investigated actor as a wallet."),
		actorAcceptanceCreatedTokens(input.Dossier),
		actorAcceptanceFunding(input.FundingOrigin, network),
		actorAcceptanceRecipients(input.Dossier),
		actorAcceptanceRecipientHolderMatch(input.Dossier),
		actorAcceptanceLiquidity(input.Dossier),
		actorAcceptanceRepeatActors(input.Dossier),
		actorAcceptanceDirectCreatorHolder(input.Dossier),
		actorAcceptanceVerdictItem(verdict),
	}

	result := ActorAcceptanceResult{
		ContractVersion:     ActorAcceptanceContractVersion,
		ActorRulesetVersion: ActorDefenseRulesetVersion,
		Wallet:              wallet,
		Network:             network,
		Items:               items,
		Verdict:             verdict,
	}
	for _, item := range items {
		switch item.Status {
		case ActorAcceptancePass:
			result.PassCount++
		case ActorAcceptanceFail:
			result.FailCount++
		default:
			result.NotInvestigatedCount++
		}
	}
	switch {
	case result.FailCount > 0:
		result.Status = ActorAcceptanceFail
	case result.NotInvestigatedCount > 0:
		result.Status = "partial"
	default:
		result.Status = ActorAcceptancePass
	}
	result.AcceptanceHash = actorAcceptanceHash(result)
	return result
}

func actorAcceptanceCreatedTokens(dossier ActorDefenseDossier) ActorAcceptanceItem {
	rows := actorAcceptanceEvidenceForRelations(dossier.Evidence, "created_token")
	if len(rows) > 0 {
		return actorAcceptanceItem("AC-03", "Created token mints are listed with evidence", ActorAcceptancePass, "verified_or_observed", fmt.Sprintf("%d creator-to-mint evidence line(s) are complete.", len(rows)), rows)
	}
	if dossier.Track.CreatedTokenCount > 0 || actorAcceptanceTokenRoleCount(dossier.Tokens, "creator_deployer") > 0 {
		return actorAcceptanceItemWithLimit("AC-03", "Created token mints are listed with evidence", ActorAcceptanceFail, "not_verified", "Created-token observations exist, but no complete creator-to-mint evidence line satisfies the canonical evidence contract.", "A creator-token claim requires signature, slot, timestamp, source wallet, destination mint, program and verification status.")
	}
	return actorAcceptanceItemWithLimit("AC-03", "Created token mints are listed with evidence", ActorAcceptanceNotInvestigated, "not_investigated", "No creator-to-mint evidence was investigated or persisted for this wallet.", "Absence of a persisted creator relation is not evidence that the wallet created no tokens.")
}

func actorAcceptanceFunding(origin ActorFundingOrigin, network string) ActorAcceptanceItem {
	row, ok := actorAcceptanceFundingLine(origin, network)
	if ok {
		summary := "Funding source observed; identity remains limited to an on-chain wallet."
		if strings.Contains(strings.ToLower(origin.TrailStatus), "cex") {
			summary = "Trail ends at CEX — identity opaque."
		}
		return actorAcceptanceItem("AC-04", "Initial funding origin is shown", ActorAcceptancePass, normalizeActorEvidenceStatus(origin.VerificationStatus), summary, []ActorAcceptanceEvidenceLine{row})
	}
	if origin.Status == "not_investigated" || origin.Status == "stored_evidence_only" || origin.TrailStatus == "not_investigated" {
		return actorAcceptanceItemWithLimit("AC-04", "Initial funding origin is shown", ActorAcceptanceNotInvestigated, "not_investigated", "Funding origin was not investigated.", actorAcceptanceFirstLimitation(origin.Limitations, "Funding-origin collection did not produce a complete evidence line."))
	}
	return actorAcceptanceItemWithLimit("AC-04", "Initial funding origin is shown", ActorAcceptanceFail, "unavailable", "Funding-origin collection ran but did not produce a complete canonical evidence line.", actorAcceptanceFirstLimitation(origin.Limitations, "Missing or malformed funding evidence fails closed."))
}

func actorAcceptanceRecipients(dossier ActorDefenseDossier) ActorAcceptanceItem {
	rows := actorAcceptanceEvidenceForRelations(dossier.Evidence, "initial_token_recipient", "creator_recipient_in_window")
	if len(rows) > 0 {
		return actorAcceptanceItem("AC-05", "Creator token exits and recipient wallets are resolved", ActorAcceptancePass, "verified", fmt.Sprintf("%d mint-specific ATA recipient transfer line(s) are complete.", len(rows)), rows)
	}
	return actorAcceptanceItemWithLimit("AC-05", "Creator token exits and recipient wallets are resolved", ActorAcceptanceNotInvestigated, "not_investigated", "No complete mint-specific ATA recipient transfer evidence is available.", "Recipient-wide wallet history is intentionally forbidden; only the relevant mint ATA path is accepted.")
}

func actorAcceptanceRecipientHolderMatch(dossier ActorDefenseDossier) ActorAcceptanceItem {
	rows := actorAcceptanceEvidenceForRelationsWithMetadata(dossier.Evidence, []string{"initial_token_recipient", "creator_recipient_in_window"}, "matches_top_holder")
	if len(rows) > 0 {
		matched := 0
		for _, item := range dossier.Evidence {
			if actorAcceptanceRelationIn(item.Relation, "initial_token_recipient", "creator_recipient_in_window") && actorAcceptanceMetadataBool(item.Metadata, "matches_top_holder") {
				matched++
			}
		}
		return actorAcceptanceItem("AC-06", "Recipients are compared with top-holder evidence", ActorAcceptancePass, "verified", fmt.Sprintf("Top-holder comparison is recorded for recipient evidence; %d recipient(s) matched a top-holder snapshot.", matched), rows)
	}
	if len(actorAcceptanceEvidenceForRelations(dossier.Evidence, "initial_token_recipient", "creator_recipient_in_window")) > 0 {
		return actorAcceptanceItemWithLimit("AC-06", "Recipients are compared with top-holder evidence", ActorAcceptanceFail, "not_verified", "Recipient transfers exist, but top-holder comparison materialization is missing.", "A zero match is valid only when the comparison field and holder-source status were actually recorded.")
	}
	return actorAcceptanceItemWithLimit("AC-06", "Recipients are compared with top-holder evidence", ActorAcceptanceNotInvestigated, "not_investigated", "Recipient-to-top-holder comparison was not investigated.", "No recipient transfer evidence was available to compare.")
}

func actorAcceptanceLiquidity(dossier ActorDefenseDossier) ActorAcceptanceItem {
	rows := actorAcceptanceEvidenceForRelations(dossier.Evidence, "liquidity_add_activity", "liquidity_remove_activity")
	if len(rows) > 0 {
		return actorAcceptanceItem("AC-07", "Liquidity add or remove activity is shown with signatures", ActorAcceptancePass, "verified_or_observed", fmt.Sprintf("%d complete liquidity evidence line(s) are available.", len(rows)), rows)
	}
	return actorAcceptanceItemWithLimit("AC-07", "Liquidity add or remove activity is shown with signatures", ActorAcceptanceNotInvestigated, "not_investigated", "Liquidity activity was not established by a complete evidence line in this narrow acceptance slice.", "Cross-token and liquidity expansion remains outside the first narrow wallet acceptance slice.")
}

func actorAcceptanceRepeatActors(dossier ActorDefenseDossier) ActorAcceptanceItem {
	creatorRows := actorAcceptanceEvidenceForRelations(dossier.Evidence, "created_token")
	creatorMints := map[string]bool{}
	for _, row := range creatorRows {
		if strings.TrimSpace(row.TokenMint) != "" {
			creatorMints[row.TokenMint] = true
		}
	}
	holderRows := actorAcceptanceEvidenceForRelations(dossier.Evidence, "dominant_holder_reuse", "dominant_holder_recurrence", "cross_token_related_actor", "cross_token_creator_holder_transfer")
	if len(creatorMints) >= 2 && len(holderRows) > 0 {
		rows := append(append([]ActorAcceptanceEvidenceLine{}, creatorRows...), holderRows...)
		actorAcceptanceSortEvidence(rows)
		return actorAcceptanceItem("AC-08", "Creator and dominant-holder recurrence is found across tokens", ActorAcceptancePass, "verified_or_observed", fmt.Sprintf("Creator recurrence spans %d mint(s), with %d complete holder/related-actor recurrence line(s).", len(creatorMints), len(holderRows)), rows)
	}
	if len(creatorMints) >= 2 || dossier.Track.CreatedTokenCount >= 2 || dossier.Track.DominantHolderTokenCount >= 2 {
		return actorAcceptanceItemWithLimit("AC-08", "Creator and dominant-holder recurrence is found across tokens", ActorAcceptanceFail, "not_verified", "Cross-token recurrence counters or creator evidence exist, but the complete creator-plus-holder evidence requirement is not satisfied.", "Observed recurrence does not prove identity, intent or common control; exact evidence lines are required.")
	}
	return actorAcceptanceItemWithLimit("AC-08", "Creator and dominant-holder recurrence is found across tokens", ActorAcceptanceNotInvestigated, "not_investigated", "Cross-token creator and holder recurrence was not investigated.", "The narrow first slice may legitimately leave this item not investigated.")
}

func actorAcceptanceDirectCreatorHolder(dossier ActorDefenseDossier) ActorAcceptanceItem {
	rows := actorAcceptanceEvidenceForRelations(dossier.Evidence, "direct_sol_transfer_out", "direct_token_transfer_out", "cross_token_creator_holder_transfer")
	verified := make([]ActorAcceptanceEvidenceLine, 0, len(rows))
	for _, row := range rows {
		if row.VerificationStatus == "verified" {
			verified = append(verified, row)
		}
	}
	if len(verified) > 0 {
		return actorAcceptanceItem("AC-09", "Direct creator to dominant-holder relation is proven or explicitly withheld", ActorAcceptancePass, "verified", "Direct creator-to-holder relation is transaction-backed.", verified)
	}
	return actorAcceptanceItem("AC-09", "Direct creator to dominant-holder relation is proven or explicitly withheld", ActorAcceptancePass, "not_verified", "Direct creator → dominant-holder relation: NOT VERIFIED", []ActorAcceptanceEvidenceLine{})
}

func actorAcceptanceVerdictItem(verdict ActorAcceptanceVerdict) ActorAcceptanceItem {
	ruleIDs := make([]string, 0, len(verdict.TriggeredRules))
	completeRules := true
	for _, hit := range verdict.TriggeredRules {
		ruleIDs = append(ruleIDs, strings.TrimSpace(hit.RuleID))
		if strings.TrimSpace(hit.RuleID) == "" || len(hit.EvidenceKeys) == 0 {
			completeRules = false
		}
	}
	sort.Strings(ruleIDs)
	if verdict.Signed && verdict.Signature != "" && verdict.Grade != "-" && verdict.RulesetVersion != "" && len(ruleIDs) > 0 && completeRules {
		summary := fmt.Sprintf("Verdict: %s — triggered by rules [%s] — ruleset %s", verdict.Grade, strings.Join(ruleIDs, ", "), verdict.RulesetVersion)
		return actorAcceptanceItem("AC-10", "One evidence-backed deterministic verdict is produced", ActorAcceptancePass, "verified", summary, []ActorAcceptanceEvidenceLine{{Kind: "control", EvidenceKey: "actor-verdict:" + verdict.Signature, Relation: "deterministic_rule_verdict", SourceWallet: "koschei-rules", DestinationWallet: "actor-case", Amount: "not_applicable", Program: "koschei-actor-defense-rules", VerificationStatus: "verified", EvidenceSource: verdict.RulesetVersion}})
	}
	return actorAcceptanceItemWithLimit("AC-10", "One evidence-backed deterministic verdict is produced", ActorAcceptanceFail, "not_verified", "No evidence-backed letter-grade verdict satisfies the actor ruleset contract.", "A signed hash without triggered rule evidence is insufficient; absence of evidence is not an A grade.")
}

func actorAcceptanceControlItem(id, question string, passed bool, relation, wallet, summary string) ActorAcceptanceItem {
	status := ActorAcceptancePass
	state := "verified"
	if !passed {
		status = ActorAcceptanceFail
		state = "unavailable"
	}
	return actorAcceptanceItem(id, question, status, state, summary, []ActorAcceptanceEvidenceLine{{Kind: "control", EvidenceKey: relation + ":" + wallet, Relation: relation, SourceWallet: wallet, DestinationWallet: wallet, Amount: "not_applicable", Program: "koschei-owner-router", VerificationStatus: state, EvidenceSource: "owner_request_contract"}})
}

func actorAcceptanceItem(id, question, status, evidenceState, summary string, evidence []ActorAcceptanceEvidenceLine) ActorAcceptanceItem {
	actorAcceptanceSortEvidence(evidence)
	return ActorAcceptanceItem{ID: id, Question: question, Status: status, EvidenceState: evidenceState, Summary: summary, Evidence: evidence, Limitations: []string{}}
}

func actorAcceptanceItemWithLimit(id, question, status, evidenceState, summary, limitation string) ActorAcceptanceItem {
	return ActorAcceptanceItem{ID: id, Question: question, Status: status, EvidenceState: evidenceState, Summary: summary, Evidence: []ActorAcceptanceEvidenceLine{}, Limitations: []string{strings.TrimSpace(limitation)}}
}

func actorAcceptanceEvidenceForRelations(items []ActorDefenseEvidenceRecord, relations ...string) []ActorAcceptanceEvidenceLine {
	out := []ActorAcceptanceEvidenceLine{}
	for _, item := range items {
		if !actorAcceptanceRelationIn(item.Relation, relations...) {
			continue
		}
		if row, ok := actorAcceptanceChainLine(item); ok {
			out = append(out, row)
		}
	}
	actorAcceptanceSortEvidence(out)
	return out
}

func actorAcceptanceEvidenceForRelationsWithMetadata(items []ActorDefenseEvidenceRecord, relations []string, metadataKey string) []ActorAcceptanceEvidenceLine {
	out := []ActorAcceptanceEvidenceLine{}
	for _, item := range items {
		if !actorAcceptanceRelationIn(item.Relation, relations...) || !actorAcceptanceMetadataHas(item.Metadata, metadataKey) {
			continue
		}
		if row, ok := actorAcceptanceChainLine(item); ok {
			out = append(out, row)
		}
	}
	actorAcceptanceSortEvidence(out)
	return out
}

func actorAcceptanceChainLine(item ActorDefenseEvidenceRecord) (ActorAcceptanceEvidenceLine, bool) {
	status := normalizeActorEvidenceStatus(item.VerificationStatus)
	source := actorAcceptanceMetadataString(item.Metadata, "source_wallet")
	if source == "" {
		source = strings.TrimSpace(item.ActorWallet)
	}
	destination := actorAcceptanceMetadataString(item.Metadata, "destination_wallet")
	if destination == "" {
		destination = strings.TrimSpace(item.CounterpartID)
	}
	program := actorAcceptanceMetadataString(item.Metadata, "program")
	amount := "not_applicable"
	if item.TokenAmount != 0 || strings.TrimSpace(item.TokenMint) != "" {
		amount = fmt.Sprintf("%g %s", item.TokenAmount, strings.TrimSpace(item.TokenMint))
	} else if item.AmountNative != 0 {
		amount = fmt.Sprintf("%g SOL", item.AmountNative)
	}
	if strings.TrimSpace(item.Signature) == "" || item.Slot <= 0 || item.ObservedAt.IsZero() || source == "" || destination == "" || program == "" || status == "" {
		return ActorAcceptanceEvidenceLine{}, false
	}
	return ActorAcceptanceEvidenceLine{
		Kind: "chain", EvidenceKey: strings.TrimSpace(item.EvidenceKey), Relation: strings.TrimSpace(item.Relation),
		Signature: strings.TrimSpace(item.Signature), Slot: item.Slot, Timestamp: item.ObservedAt.UTC(),
		SourceWallet: source, DestinationWallet: destination, Amount: amount, Program: program,
		VerificationStatus: status, TokenMint: strings.TrimSpace(item.TokenMint), EvidenceSource: strings.TrimSpace(item.Source),
	}, true
}

func actorAcceptanceFundingLine(origin ActorFundingOrigin, network string) (ActorAcceptanceEvidenceLine, bool) {
	item, ok := ActorFundingOriginEvidence(origin, network)
	if !ok {
		return ActorAcceptanceEvidenceLine{}, false
	}
	return actorAcceptanceChainLine(item)
}

func actorAcceptanceVerdict(verdict ActorDefenseRuleVerdict) ActorAcceptanceVerdict {
	out := ActorAcceptanceVerdict{
		Grade: verdict.Grade, Verdict: verdict.Verdict, RulesetVersion: verdict.RulesetVersion,
		TriggeredRules: append([]ActorDefenseRuleHit{}, verdict.TriggeredRules...),
		WatchFlags: append([]ActorDefenseRuleHit{}, verdict.WatchFlags...),
		DecisionPath: append([]string{}, verdict.DecisionPath...), Signed: verdict.Signed, Signature: verdict.Signature,
	}
	actorRuleSortHits(out.TriggeredRules)
	actorRuleSortHits(out.WatchFlags)
	return out
}

func actorAcceptanceHash(result ActorAcceptanceResult) string {
	copy := result
	copy.AcceptanceHash = ""
	raw, _ := json.Marshal(copy)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func actorAcceptanceSortEvidence(items []ActorAcceptanceEvidenceLine) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		if items[i].Slot != items[j].Slot {
			return items[i].Slot < items[j].Slot
		}
		if items[i].Signature != items[j].Signature {
			return items[i].Signature < items[j].Signature
		}
		return items[i].EvidenceKey < items[j].EvidenceKey
	})
}

func actorAcceptanceRelationIn(value string, allowed ...string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, candidate := range allowed {
		if value == strings.ToLower(strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func actorAcceptanceTokenRoleCount(items []ActorDefenseTokenObservation, role string) int {
	count := 0
	for _, item := range items {
		for _, candidate := range item.Roles {
			if strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(role)) {
				count++
				break
			}
		}
	}
	return count
}

func actorAcceptanceMetadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, ok := metadata[key]
	if !ok || value == nil {
		return ""
	}
	out := strings.TrimSpace(fmt.Sprint(value))
	if out == "<nil>" {
		return ""
	}
	return out
}

func actorAcceptanceMetadataHas(metadata map[string]any, key string) bool {
	if metadata == nil {
		return false
	}
	_, ok := metadata[key]
	return ok
}

func actorAcceptanceMetadataBool(metadata map[string]any, key string) bool {
	if metadata == nil {
		return false
	}
	switch value := metadata[key].(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(strings.TrimSpace(value), "true")
	default:
		return false
	}
}

func actorAcceptanceFirstLimitation(items []string, fallback string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return fallback
}
