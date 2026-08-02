package services

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ActorFundingOriginOptions bounds a selective wallet investigation. This
// routine is never used by the broad Pump discovery pipeline.
type ActorFundingOriginOptions struct {
	PageSize                  int
	MaxPages                  int
	OldestTransactionsToParse int
}

type ActorFundingOrigin struct {
	Wallet             string               `json:"wallet"`
	Status             string               `json:"status"`
	HistoryComplete    bool                 `json:"history_complete"`
	SourceWallet       string               `json:"source_wallet,omitempty"`
	DestinationWallet  string               `json:"destination_wallet,omitempty"`
	AmountSOL          float64              `json:"amount_sol,omitempty"`
	Signature          string               `json:"signature,omitempty"`
	Slot               int64                `json:"slot,omitempty"`
	ObservedAt         time.Time            `json:"observed_at,omitempty"`
	Program            string               `json:"program,omitempty"`
	InstructionType    string               `json:"instruction_type,omitempty"`
	VerificationStatus string               `json:"verification_status"`
	TrailStatus        string               `json:"trail_status"`
	IdentityScope      string               `json:"identity_scope"`
	PagesScanned       int                  `json:"pages_scanned"`
	SignaturesScanned  int                  `json:"signatures_scanned"`
	TransactionsParsed int                  `json:"transactions_parsed"`
	ResultState        string               `json:"result_state"`
	Boundary           ActorFundingBoundary `json:"boundary"`
	Limitations        []string             `json:"limitations"`
}

type actorFundingCandidate struct {
	Source          string
	Destination     string
	Lamports        int64
	Signature       string
	Slot            int64
	ObservedAt      time.Time
	InstructionType string
	SourceSigned    bool
}

func FindActorFundingOrigin(ctx context.Context, rpcURL, wallet string, options ActorFundingOriginOptions) (ActorFundingOrigin, error) {
	wallet = strings.TrimSpace(wallet)
	rpcURL = strings.TrimSpace(rpcURL)
	result := ActorFundingOrigin{
		Wallet:             wallet,
		Status:             "not_investigated",
		VerificationStatus: "unverified",
		TrailStatus:        "not_investigated",
		IdentityScope:      "onchain_wallet_only",
		Limitations:        []string{},
	}
	if wallet == "" {
		return result, fmt.Errorf("actor wallet is required")
	}
	pageSize, maxPages, parseLimit := normalizeActorFundingOptions(options)
	initializeActorFundingBoundary(&result, pageSize, maxPages, parseLimit)
	if rpcURL == "" {
		result.Boundary.Kind = "rpc_unavailable"
		result.Boundary.Reason = "Solana RPC is unavailable; the collector did not walk chain history."

		result.Status = "rpc_unavailable"
		result.TrailStatus = "not_investigated"
		result.Limitations = append(result.Limitations, "Solana RPC yapılandırılmadığı için funding origin araştırılmadı.")
		return result, nil
	}
	signatures := make([]SolanaSignatureInfo, 0, pageSize*maxPages)
	seen := map[string]bool{}
	before := ""
	for page := 0; page < maxPages && ctx.Err() == nil; page++ {
		rows, err := SolanaGetSignaturesForAddressPage(ctx, rpcURL, wallet, SolanaSignaturePageOptions{Limit: pageSize, Before: before})
		if err != nil {
			if len(signatures) == 0 {
				result.Status = "signature_history_failed"
				result.TrailStatus = "not_investigated"
				result.Limitations = append(result.Limitations, "Wallet imza geçmişi sayfalanırken RPC hatası oluştu: "+compactActorFundingError(err))
				return result, nil
			}
			result.Limitations = append(result.Limitations, "İmza geçmişi kısmi kaldı; sonraki sayfa alınamadı: "+compactActorFundingError(err))
			break
		}
		result.PagesScanned++
		for _, row := range rows {
			sig := strings.TrimSpace(row.Signature)
			if sig == "" || seen[sig] {
				continue
			}
			seen[sig] = true
			signatures = append(signatures, row)
			observeActorFundingSignature(&result, row)
		}
		if len(rows) < pageSize {
			result.HistoryComplete = true
			break
		}
		last := strings.TrimSpace(rows[len(rows)-1].Signature)
		if last == "" || last == before {
			result.Limitations = append(result.Limitations, "RPC imza cursor'ı ilerlemedi; geçmiş tamamlandı kabul edilmedi.")
			break
		}
		before = last
	}
	if ctx.Err() != nil {
		result.Limitations = append(result.Limitations, "Funding-origin süresi doldu; taranan pencere kısmi kaldı.")
	}
	result.SignaturesScanned = len(signatures)
	syncActorFundingBoundaryCounts(&result)
	pageBoundaryReached := result.PagesScanned >= maxPages && !result.HistoryComplete && ctx.Err() == nil
	if len(signatures) == 0 {
		if pageBoundaryReached {
			markActorFundingPageBoundary(&result, pageSize, maxPages)
		} else if result.HistoryComplete {
			markActorFundingComplete(&result, "history_complete_no_signatures")
		}
		result.Status = "no_signatures"
		result.TrailStatus = "no_onchain_history_observed"
		result.VerificationStatus = "unverified"
		return result, nil
	}

	sort.SliceStable(signatures, func(i, j int) bool {
		left, right := actorFundingSignatureTime(signatures[i]), actorFundingSignatureTime(signatures[j])
		if !left.Equal(right) {
			if left.IsZero() {
				return false
			}
			if right.IsZero() {
				return true
			}
			return left.Before(right)
		}
		if signatures[i].Slot != signatures[j].Slot {
			return signatures[i].Slot < signatures[j].Slot
		}
		return signatures[i].Signature < signatures[j].Signature
	})

	candidates := make([]actorFundingCandidate, 0, 4)
	parseBoundaryReached := false
	for index, signature := range signatures {
		if result.TransactionsParsed >= parseLimit {
			parseBoundaryReached = index < len(signatures)
			break
		}
		if ctx.Err() != nil {
			break
		}
		if signature.Err != nil || strings.TrimSpace(signature.Signature) == "" {
			continue
		}
		tx, err := SolanaGetTransactionJSONParsed(ctx, rpcURL, signature.Signature)
		if err != nil {
			continue
		}
		txMap := map[string]any(tx)
		meta := actorFundingMap(txMap["meta"])
		if meta["err"] != nil {
			continue
		}
		result.TransactionsParsed++
		message := actorFundingMap(actorFundingMap(txMap["transaction"])["message"])
		signers := actorFundingSigners(message)
		observedAt := actorFundingTransactionTime(signature, txMap)
		for _, instruction := range actorFundingInstructions(message, meta) {
			candidate, ok := actorFundingInstructionCandidate(wallet, signature, observedAt, signers, instruction)
			if ok {
				candidates = append(candidates, candidate)
			}
		}
	}

	syncActorFundingBoundaryCounts(&result)
	if len(candidates) == 0 {
		switch {
		case parseBoundaryReached:
			markActorFundingParseBoundary(&result, parseLimit)
		case pageBoundaryReached:
			markActorFundingPageBoundary(&result, pageSize, maxPages)
		case result.HistoryComplete:
			markActorFundingComplete(&result, "history_complete_no_direct_funding")
		case ctx.Err() != nil:
			result.Boundary.Kind = "context_deadline"
			result.Boundary.Reason = "The collector stopped before reaching a chain or configured boundary."
		}
		result.Status = "funding_not_observed"
		result.TrailStatus = "no_direct_system_funding_observed"
		result.VerificationStatus = "unverified"
		if !result.HistoryComplete {
			result.Limitations = append(result.Limitations, "İmza geçmişi bütçe sınırında kaldı; daha eski funding işlemleri taranmamış olabilir.")
		}
		return result, nil
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if !candidates[i].ObservedAt.Equal(candidates[j].ObservedAt) {
			if candidates[i].ObservedAt.IsZero() {
				return false
			}
			if candidates[j].ObservedAt.IsZero() {
				return true
			}
			return candidates[i].ObservedAt.Before(candidates[j].ObservedAt)
		}
		if candidates[i].Slot != candidates[j].Slot {
			return candidates[i].Slot < candidates[j].Slot
		}
		if candidates[i].Signature != candidates[j].Signature {
			return candidates[i].Signature < candidates[j].Signature
		}
		return candidates[i].Source < candidates[j].Source
	})
	chosen := candidates[0]
	result.SourceWallet = chosen.Source
	result.DestinationWallet = chosen.Destination
	result.AmountSOL = float64(chosen.Lamports) / 1e9
	result.Signature = chosen.Signature
	result.Slot = chosen.Slot
	result.ObservedAt = chosen.ObservedAt
	result.Program = "system"
	result.InstructionType = chosen.InstructionType
	result.TrailStatus = "source_wallet_observed"
	switch {
	case parseBoundaryReached:
		markActorFundingParseBoundary(&result, parseLimit)
		result.Boundary.Reason = "A funding transfer was observed inside the scanned window, but the parse boundary prevents it from being published as the initial funding origin."
	case pageBoundaryReached:
		markActorFundingPageBoundary(&result, pageSize, maxPages)
		result.Boundary.Reason = "A funding transfer was observed inside the scanned window, but the signature boundary prevents it from being published as the initial funding origin."
	default:
		markActorFundingComplete(&result, "funding_transfer_verified")
	}
	if chosen.SourceSigned && chosen.Signature != "" && chosen.Slot > 0 && !chosen.ObservedAt.IsZero() {
		result.VerificationStatus = "verified"
	} else {
		result.VerificationStatus = "observed"
	}
	if result.HistoryComplete {
		result.Status = "initial_funding_observed"
	} else {
		result.Status = "oldest_funding_within_scanned_window"
		result.Limitations = append(result.Limitations, "Bu transfer doğrulanmıştır ancak taranan imza geçmişi tamamlanmadığı için kesin ilk funding olarak adlandırılmaz.")
	}
	result.Limitations = append(result.Limitations, "Funding source yalnız zincir üstü cüzdan olarak raporlanır; CEX veya gerçek kişi etiketi ayrı doğrulanmadıkça kimlik iddiası üretilmez.")
	return result, nil
}

func ActorFundingOriginEvidence(origin ActorFundingOrigin, network string) (ActorDefenseEvidenceRecord, bool) {
	if origin.ResultState == ActorFundingResultBounded {
		return ActorDefenseEvidenceRecord{}, false
	}
	if strings.TrimSpace(origin.SourceWallet) == "" || strings.TrimSpace(origin.DestinationWallet) == "" || strings.TrimSpace(origin.Signature) == "" {
		return ActorDefenseEvidenceRecord{}, false
	}
	status := normalizeActorEvidenceStatus(origin.VerificationStatus)
	if status == "unverified" {
		return ActorDefenseEvidenceRecord{}, false
	}
	relation := "oldest_funding_in_window"
	evidenceSuffix := ":oldest_funding_window"
	if origin.HistoryComplete {
		relation = "initial_funding_in"
		evidenceSuffix = ":initial_funding"
	}
	return ActorDefenseEvidenceRecord{
		Network:            normalizeRadarNetwork(network),
		ActorWallet:        strings.TrimSpace(origin.Wallet),
		CounterpartKind:    "wallet",
		CounterpartID:      strings.TrimSpace(origin.SourceWallet),
		Relation:           relation,
		VerificationStatus: status,
		EvidenceKey:        strings.TrimSpace(origin.Signature) + evidenceSuffix,
		Source:             "solana_jsonparsed_instruction",
		Signature:          strings.TrimSpace(origin.Signature),
		Slot:               origin.Slot,
		ObservedAt:         origin.ObservedAt.UTC(),
		AmountNative:       origin.AmountSOL,
		Metadata: map[string]any{
			"actor_role":             "funded_wallet",
			"source_wallet":          strings.TrimSpace(origin.SourceWallet),
			"destination_wallet":     strings.TrimSpace(origin.DestinationWallet),
			"program":                "system",
			"instruction_type":       strings.TrimSpace(origin.InstructionType),
			"history_complete":       origin.HistoryComplete,
			"funding_status":         origin.Status,
			"trail_status":           origin.TrailStatus,
			"identity_scope":         origin.IdentityScope,
			"persistent_actor_index": true,
		},
	}, true
}

func normalizeActorFundingOptions(options ActorFundingOriginOptions) (pageSize, maxPages, parseLimit int) {
	pageSize = options.PageSize
	if pageSize <= 0 {
		pageSize = 250
	} else if pageSize > actorFundingMaxPageSize {
		pageSize = actorFundingMaxPageSize
	}
	maxPages = options.MaxPages
	if maxPages <= 0 {
		maxPages = 8
	} else if maxPages > actorFundingMaxPages {
		maxPages = actorFundingMaxPages
	}
	parseLimit = options.OldestTransactionsToParse
	if parseLimit <= 0 {
		parseLimit = 60
	} else if parseLimit > actorFundingMaxParseLimit {
		parseLimit = actorFundingMaxParseLimit
	}
	return
}

func actorFundingInstructionCandidate(wallet string, signature SolanaSignatureInfo, observedAt time.Time, signers map[string]bool, instruction map[string]any) (actorFundingCandidate, bool) {
	program := strings.ToLower(strings.TrimSpace(actorFundingString(instruction["program"])))
	parsed := actorFundingMap(instruction["parsed"])
	kind := strings.ToLower(strings.TrimSpace(actorFundingString(parsed["type"])))
	info := actorFundingMap(parsed["info"])
	if program != "system" {
		return actorFundingCandidate{}, false
	}
	source := strings.TrimSpace(actorFundingString(info["source"]))
	destination := strings.TrimSpace(actorFundingString(info["destination"]))
	switch kind {
	case "createaccount", "createaccountwithseed":
		destination = strings.TrimSpace(firstActorFundingString(actorFundingString(info["newAccount"]), actorFundingString(info["newAccountPubkey"]), destination))
	case "transfer", "transferwithseed":
		// source/destination already normalized above.
	default:
		return actorFundingCandidate{}, false
	}
	lamports := actorFundingInt64(info["lamports"])
	if destination != wallet || source == "" || source == wallet || lamports <= 0 {
		return actorFundingCandidate{}, false
	}
	return actorFundingCandidate{
		Source:          source,
		Destination:     destination,
		Lamports:        lamports,
		Signature:       strings.TrimSpace(signature.Signature),
		Slot:            signature.Slot,
		ObservedAt:      observedAt,
		InstructionType: kind,
		SourceSigned:    signers[source],
	}, true
}

func actorFundingInstructions(message, meta map[string]any) []map[string]any {
	out := []map[string]any{}
	appendRows := func(raw any) {
		items, _ := raw.([]any)
		for _, item := range items {
			row := actorFundingMap(item)
			if len(row) > 0 {
				out = append(out, row)
			}
		}
	}
	appendRows(message["instructions"])
	inner, _ := meta["innerInstructions"].([]any)
	for _, item := range inner {
		appendRows(actorFundingMap(item)["instructions"])
	}
	return out
}

func actorFundingSigners(message map[string]any) map[string]bool {
	out := map[string]bool{}
	items, _ := message["accountKeys"].([]any)
	for _, item := range items {
		switch value := item.(type) {
		case string:
			// Legacy string account keys do not expose signer state.
		case map[string]any:
			pubkey := strings.TrimSpace(actorFundingString(value["pubkey"]))
			if pubkey != "" && actorFundingBool(value["signer"]) {
				out[pubkey] = true
			}
		}
	}
	return out
}

func actorFundingTransactionTime(signature SolanaSignatureInfo, tx map[string]any) time.Time {
	if unix := actorFundingInt64(tx["blockTime"]); unix > 0 {
		return time.Unix(unix, 0).UTC()
	}
	return actorFundingSignatureTime(signature)
}

func actorFundingSignatureTime(signature SolanaSignatureInfo) time.Time {
	if signature.BlockTime != nil && *signature.BlockTime > 0 {
		return time.Unix(*signature.BlockTime, 0).UTC()
	}
	return time.Time{}
}

func actorFundingMap(value any) map[string]any {
	if result, ok := value.(map[string]any); ok {
		return result
	}
	return map[string]any{}
}

func actorFundingString(value any) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func actorFundingInt64(value any) int64 {
	switch typed := value.(type) {
	case int64:
		return typed
	case int:
		return int64(typed)
	case float64:
		return int64(typed)
	case string:
		parsed, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return parsed
	default:
		return 0
	}
}

func actorFundingBool(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		parsed, _ := strconv.ParseBool(strings.TrimSpace(typed))
		return parsed
	default:
		return false
	}
}

func firstActorFundingString(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" && value != "<nil>" {
			return value
		}
	}
	return ""
}

func compactActorFundingError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if len(message) > 240 {
		message = message[:240]
	}
	return message
}
