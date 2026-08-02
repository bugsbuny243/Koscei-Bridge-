package services

import "strings"

const (
	ActorFundingResultVerified = "verified"
	ActorFundingResultBounded  = "bounded"
	ActorFundingResultMissing  = "missing"

	actorFundingMaxPageSize   = 1000
	actorFundingMaxPages      = 20
	actorFundingMaxParseLimit = 250
)

type ActorFundingBoundary struct {
	Kind                    string `json:"kind"`
	Reason                  string `json:"reason,omitempty"`
	EffectivePageSize       int    `json:"effective_page_size"`
	EffectiveMaxPages       int    `json:"effective_max_pages"`
	EffectiveSignatureLimit int    `json:"effective_signature_limit"`
	EffectiveParseLimit     int    `json:"effective_transaction_parse_limit"`
	PagesScanned            int    `json:"pages_scanned"`
	SignaturesWalked        int    `json:"signatures_walked"`
	TransactionsParsed      int    `json:"transactions_parsed"`
	OldestSignature         string `json:"oldest_signature,omitempty"`
	OldestSlot              int64  `json:"oldest_slot,omitempty"`
	ReachedConfiguredWindow bool   `json:"reached_configured_window"`
	ReachedHardCeiling      bool   `json:"reached_hard_ceiling"`
	ReachedParseLimit       bool   `json:"reached_parse_limit"`
	Raisable                bool   `json:"raisable"`
	DeeperWalkCouldChange   bool   `json:"deeper_walk_could_change"`
}

func initializeActorFundingBoundary(result *ActorFundingOrigin, pageSize, maxPages, parseLimit int) {
	if result == nil {
		return
	}
	result.ResultState = ActorFundingResultMissing
	result.Boundary = ActorFundingBoundary{
		Kind:                    "not_investigated",
		EffectivePageSize:       pageSize,
		EffectiveMaxPages:       maxPages,
		EffectiveSignatureLimit: pageSize * maxPages,
		EffectiveParseLimit:     parseLimit,
	}
}

func observeActorFundingSignature(result *ActorFundingOrigin, signature SolanaSignatureInfo) {
	if result == nil || signature.Slot <= 0 || strings.TrimSpace(signature.Signature) == "" {
		return
	}
	if result.Boundary.OldestSlot == 0 || signature.Slot < result.Boundary.OldestSlot {
		result.Boundary.OldestSlot = signature.Slot
		result.Boundary.OldestSignature = strings.TrimSpace(signature.Signature)
	}
}

func syncActorFundingBoundaryCounts(result *ActorFundingOrigin) {
	if result == nil {
		return
	}
	result.Boundary.PagesScanned = result.PagesScanned
	result.Boundary.SignaturesWalked = result.SignaturesScanned
	result.Boundary.TransactionsParsed = result.TransactionsParsed
}

func markActorFundingPageBoundary(result *ActorFundingOrigin, pageSize, maxPages int) {
	if result == nil {
		return
	}
	result.Boundary.ReachedConfiguredWindow = true
	result.Boundary.DeeperWalkCouldChange = true
	if pageSize >= actorFundingMaxPageSize && maxPages >= actorFundingMaxPages {
		result.Boundary.Kind = "hard_signature_ceiling"
		result.Boundary.Reason = "Funding origin was not reachable within the 20,000-signature hard ceiling."
		result.Boundary.ReachedHardCeiling = true
		result.Boundary.Raisable = false
	} else {
		result.Boundary.Kind = "configured_signature_window"
		result.Boundary.Reason = "Funding origin was not reachable within the effective configured signature window."
		result.Boundary.Raisable = true
	}
	result.ResultState = ActorFundingResultBounded
}

func markActorFundingParseBoundary(result *ActorFundingOrigin, parseLimit int) {
	if result == nil {
		return
	}
	result.Boundary.Kind = "transaction_parse_limit"
	result.Boundary.Reason = "Funding origin was not reachable within the effective transaction parse limit."
	result.Boundary.ReachedParseLimit = true
	result.Boundary.DeeperWalkCouldChange = true
	result.Boundary.Raisable = parseLimit < actorFundingMaxParseLimit
	result.ResultState = ActorFundingResultBounded
}

func markActorFundingComplete(result *ActorFundingOrigin, kind string) {
	if result == nil {
		return
	}
	result.ResultState = ActorFundingResultVerified
	result.Boundary.Kind = kind
	result.Boundary.Reason = ""
	result.Boundary.Raisable = false
	result.Boundary.DeeperWalkCouldChange = false
}
