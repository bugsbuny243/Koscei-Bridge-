package services

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	actorConstellationDirectEvidenceCap       = 512
	actorConstellationSharedSubjectCap        = 128
	actorConstellationCandidatesPerSubjectCap = 16
)

type actorConstellationCandidate struct {
	Match    ActorOperationalMatch
	Evidence []ActorConstellationEvidenceRow
}

type actorConstellationLookupResult struct {
	Candidates []actorConstellationCandidate
	Complete   bool
}

type actorConstellationCandidateStats struct {
	stats            actorOperationalMatchStats
	counterparts     map[string]struct{}
	relations        map[string]struct{}
	subjectTokens    map[string]struct{}
	candidateTokens  map[string]struct{}
	fundingSources   map[string]struct{}
	evidenceByID     map[string]ActorConstellationEvidenceRow
}

func (s *ActorDefenseStore) loadBoundedActorConstellationCandidates(ctx context.Context, wallet, network string, limit int) (actorConstellationLookupResult, error) {
	wallet = strings.TrimSpace(wallet)
	network = normalizeRadarNetwork(network)
	if s == nil || s.DB == nil {
		return actorConstellationLookupResult{}, fmt.Errorf("actor defense database is unavailable")
	}
	if wallet == "" {
		return actorConstellationLookupResult{}, fmt.Errorf("actor wallet is required")
	}
	if limit <= 0 || limit > maxActorConstellationFanout+1 {
		limit = defaultActorConstellationFanout + 1
	}

	rowsByWallet := map[string]*actorConstellationCandidateStats{}
	ensure := func(candidate string) *actorConstellationCandidateStats {
		candidate = strings.TrimSpace(candidate)
		row := rowsByWallet[candidate]
		if row == nil {
			row = &actorConstellationCandidateStats{
				stats:           actorOperationalMatchStats{Wallet: candidate},
				counterparts:    map[string]struct{}{},
				relations:       map[string]struct{}{},
				subjectTokens:   map[string]struct{}{},
				candidateTokens: map[string]struct{}{},
				fundingSources:  map[string]struct{}{},
				evidenceByID:    map[string]ActorConstellationEvidenceRow{},
			}
			rowsByWallet[candidate] = row
		}
		return row
	}

	complete := true
	directCap := limit * 16
	if directCap < 64 {
		directCap = 64
	}
	if directCap > actorConstellationDirectEvidenceCap {
		directCap = actorConstellationDirectEvidenceCap
	}
	directRows, err := s.DB.QueryContext(ctx, `
		WITH eligible AS (
			SELECT id::text,
			       actor_wallet,
			       counterpart_id,
			       relation,
			       verification_status,
			       COALESCE(signature,''),
			       COALESCE(slot,0),
			       last_observed_at,
			       source_wallet,
			       destination_wallet,
			       CASE WHEN token_amount>0 THEN token_amount::text ELSE amount_native::text END AS amount,
			       CASE WHEN token_amount>0 AND btrim(COALESCE(token_mint,''))<>'' THEN token_mint ELSE 'SOL' END AS asset,
			       program,
			       count(*) OVER() AS total_rows
			FROM security_actor_evidence
			WHERE network=$2
			  AND counterpart_kind='wallet'
			  AND verification_status IN ('verified','observed')
			  AND relation IN (
			      'direct_sol_transfer_in','direct_sol_transfer_out',
			      'direct_token_transfer_in','direct_token_transfer_out',
			      'funded_by','funding_origin','funded_creator'
			  )
			  AND (
			      (actor_wallet=$1 AND counterpart_id<>$1) OR
			      (counterpart_id=$1 AND actor_wallet<>$1)
			  )
			ORDER BY (verification_status='verified') DESC,last_observed_at DESC,id DESC
			LIMIT $3
		)
		SELECT id,actor_wallet,counterpart_id,relation,verification_status,
		       signature,slot,last_observed_at,source_wallet,destination_wallet,
		       amount,asset,program,total_rows
		FROM eligible
	`, wallet, network, directCap)
	if err != nil {
		return actorConstellationLookupResult{}, err
	}
	for directRows.Next() {
		var evidence ActorConstellationEvidenceRow
		var actorWallet, counterpart string
		var total int64
		if err := directRows.Scan(
			&evidence.ID, &actorWallet, &counterpart, &evidence.Relation, &evidence.VerificationStatus,
			&evidence.Signature, &evidence.Slot, &evidence.Timestamp, &evidence.SourceWallet, &evidence.DestinationWallet,
			&evidence.Amount, &evidence.Asset, &evidence.Program, &total,
		); err != nil {
			directRows.Close()
			return actorConstellationLookupResult{}, err
		}
		if total > int64(directCap) {
			complete = false
		}
		candidate := counterpart
		if strings.TrimSpace(actorWallet) != wallet {
			candidate = actorWallet
		}
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || candidate == wallet || !actorConstellationEvidenceComplete(evidence) {
			continue
		}
		row := ensure(candidate)
		if evidence.VerificationStatus == "verified" {
			row.stats.DirectVerifiedRelations++
		} else {
			row.stats.DirectObservedRelations++
		}
		row.evidenceByID[evidence.ID] = evidence
	}
	if err := directRows.Err(); err != nil {
		directRows.Close()
		return actorConstellationLookupResult{}, err
	}
	directRows.Close()

	subjectCap := limit * 8
	if subjectCap < 32 {
		subjectCap = 32
	}
	if subjectCap > actorConstellationSharedSubjectCap {
		subjectCap = actorConstellationSharedSubjectCap
	}
	sharedRows, err := s.DB.QueryContext(ctx, `
		WITH subject AS (
			SELECT id::text,
			       counterpart_id,
			       relation,
			       verification_status,
			       COALESCE(token_mint,'') AS token_mint,
			       COALESCE(signature,''),
			       COALESCE(slot,0),
			       last_observed_at,
			       source_wallet,
			       destination_wallet,
			       CASE WHEN token_amount>0 THEN token_amount::text ELSE amount_native::text END AS amount,
			       CASE WHEN token_amount>0 AND btrim(COALESCE(token_mint,''))<>'' THEN token_mint ELSE 'SOL' END AS asset,
			       program,
			       count(*) OVER() AS total_subject_rows
			FROM security_actor_evidence
			WHERE network=$2
			  AND actor_wallet=$1
			  AND counterpart_kind='wallet'
			  AND verification_status IN ('verified','observed')
			  AND relation IN ('funded_by','funding_origin','initial_token_recipient','creator_recipient_in_window')
			  AND COALESCE(signature,'')<>''
			  AND COALESCE(slot,0)>0
			  AND btrim(source_wallet)<>''
			  AND btrim(destination_wallet)<>''
			  AND btrim(program)<>''
			ORDER BY last_observed_at DESC,id DESC
			LIMIT $3
		)
		SELECT c.candidate_wallet,
		       s.counterpart_id,
		       s.relation,
		       s.verification_status,
		       c.candidate_status,
		       s.token_mint,
		       c.candidate_token_mint,
		       s.total_subject_rows,
		       c.total_candidate_rows,
		       s.id,s.signature,s.slot,s.last_observed_at,s.source_wallet,s.destination_wallet,s.amount,s.asset,s.program,
		       c.id,c.signature,c.slot,c.last_observed_at,c.source_wallet,c.destination_wallet,c.amount,c.asset,c.program
		FROM subject s
		JOIN LATERAL (
			SELECT actor_wallet AS candidate_wallet,
			       verification_status AS candidate_status,
			       COALESCE(token_mint,'') AS candidate_token_mint,
			       id::text,
			       COALESCE(signature,'') AS signature,
			       COALESCE(slot,0) AS slot,
			       last_observed_at,
			       source_wallet,
			       destination_wallet,
			       CASE WHEN token_amount>0 THEN token_amount::text ELSE amount_native::text END AS amount,
			       CASE WHEN token_amount>0 AND btrim(COALESCE(token_mint,''))<>'' THEN token_mint ELSE 'SOL' END AS asset,
			       program,
			       count(*) OVER() AS total_candidate_rows
			FROM security_actor_evidence c
			WHERE c.network=$2
			  AND c.actor_wallet<>$1
			  AND c.counterpart_kind='wallet'
			  AND c.counterpart_id=s.counterpart_id
			  AND c.relation=s.relation
			  AND c.verification_status IN ('verified','observed')
			  AND lower(COALESCE(c.metadata->>'source_type','')) NOT IN ('cex','exchange','hot_wallet')
			  AND lower(COALESCE(c.metadata->>'identity_opaque','false'))<>'true'
			  AND COALESCE(c.signature,'')<>''
			  AND COALESCE(c.slot,0)>0
			  AND btrim(c.source_wallet)<>''
			  AND btrim(c.destination_wallet)<>''
			  AND btrim(c.program)<>''
			ORDER BY c.last_observed_at DESC,c.id DESC
			LIMIT $4
		) c ON true
	`, wallet, network, subjectCap, actorConstellationCandidatesPerSubjectCap)
	if err != nil {
		return actorConstellationLookupResult{}, err
	}
	for sharedRows.Next() {
		var candidate, counterpart, relation, subjectStatus, candidateStatus, subjectToken, candidateToken string
		var totalSubject, totalCandidate int64
		var subjectEvidence, candidateEvidence ActorConstellationEvidenceRow
		if err := sharedRows.Scan(
			&candidate, &counterpart, &relation, &subjectStatus, &candidateStatus,
			&subjectToken, &candidateToken, &totalSubject, &totalCandidate,
			&subjectEvidence.ID, &subjectEvidence.Signature, &subjectEvidence.Slot, &subjectEvidence.Timestamp,
			&subjectEvidence.SourceWallet, &subjectEvidence.DestinationWallet, &subjectEvidence.Amount, &subjectEvidence.Asset, &subjectEvidence.Program,
			&candidateEvidence.ID, &candidateEvidence.Signature, &candidateEvidence.Slot, &candidateEvidence.Timestamp,
			&candidateEvidence.SourceWallet, &candidateEvidence.DestinationWallet, &candidateEvidence.Amount, &candidateEvidence.Asset, &candidateEvidence.Program,
		); err != nil {
			sharedRows.Close()
			return actorConstellationLookupResult{}, err
		}
		if totalSubject > int64(subjectCap) || totalCandidate > actorConstellationCandidatesPerSubjectCap {
			complete = false
		}
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || candidate == wallet {
			continue
		}
		subjectEvidence.Relation = relation
		subjectEvidence.VerificationStatus = subjectStatus
		candidateEvidence.Relation = relation
		candidateEvidence.VerificationStatus = candidateStatus
		if !actorConstellationEvidenceComplete(subjectEvidence) || !actorConstellationEvidenceComplete(candidateEvidence) {
			continue
		}
		row := ensure(candidate)
		row.counterparts[counterpart] = struct{}{}
		row.relations[relation] = struct{}{}
		if subjectToken != "" {
			row.subjectTokens[subjectToken] = struct{}{}
		}
		if candidateToken != "" {
			row.candidateTokens[candidateToken] = struct{}{}
		}
		if relation == "funded_by" || relation == "funding_origin" {
			row.fundingSources[counterpart] = struct{}{}
		}
		if subjectStatus == "verified" && candidateStatus == "verified" {
			row.stats.VerifiedOverlapCount++
		}
		row.evidenceByID[subjectEvidence.ID] = subjectEvidence
		row.evidenceByID[candidateEvidence.ID] = candidateEvidence
	}
	if err := sharedRows.Err(); err != nil {
		sharedRows.Close()
		return actorConstellationLookupResult{}, err
	}
	sharedRows.Close()

	candidates := make([]actorConstellationCandidate, 0, len(rowsByWallet))
	for candidate, row := range rowsByWallet {
		if candidate == "" || candidate == wallet || row == nil {
			continue
		}
		row.stats.SharedCounterpartCount = len(row.counterparts)
		row.stats.SharedRelationCount = len(row.relations)
		row.stats.SubjectTokenContexts = len(row.subjectTokens)
		row.stats.CandidateTokenContexts = len(row.candidateTokens)
		row.stats.SharedFundingSourceCount = len(row.fundingSources)
		match := classifyActorOperationalMatch(row.stats)
		if !actorConstellationExpansionEligible(match.Classification) {
			continue
		}
		evidence := make([]ActorConstellationEvidenceRow, 0, len(row.evidenceByID))
		for _, item := range row.evidenceByID {
			evidence = append(evidence, item)
		}
		sort.SliceStable(evidence, func(i, j int) bool {
			if !evidence[i].Timestamp.Equal(evidence[j].Timestamp) {
				return evidence[i].Timestamp.After(evidence[j].Timestamp)
			}
			return evidence[i].ID < evidence[j].ID
		})
		if len(evidence) > 8 {
			evidence = evidence[:8]
			complete = false
		}
		if !actorConstellationEvidenceSupports(match.Classification, evidence) {
			continue
		}
		candidates = append(candidates, actorConstellationCandidate{Match: match, Evidence: evidence})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		ri := actorOperationalClassificationRank(candidates[i].Match.Classification)
		rj := actorOperationalClassificationRank(candidates[j].Match.Classification)
		if ri != rj {
			return ri > rj
		}
		if candidates[i].Match.VerifiedOverlapCount != candidates[j].Match.VerifiedOverlapCount {
			return candidates[i].Match.VerifiedOverlapCount > candidates[j].Match.VerifiedOverlapCount
		}
		if candidates[i].Match.SharedCounterpartCount != candidates[j].Match.SharedCounterpartCount {
			return candidates[i].Match.SharedCounterpartCount > candidates[j].Match.SharedCounterpartCount
		}
		return candidates[i].Match.Wallet < candidates[j].Match.Wallet
	})
	if len(candidates) > limit {
		complete = false
		candidates = candidates[:limit]
	}
	return actorConstellationLookupResult{Candidates: candidates, Complete: complete}, nil
}

func actorConstellationEvidenceComplete(row ActorConstellationEvidenceRow) bool {
	return strings.TrimSpace(row.ID) != "" &&
		strings.TrimSpace(row.Signature) != "" && row.Slot > 0 && !row.Timestamp.IsZero() &&
		strings.TrimSpace(row.SourceWallet) != "" && strings.TrimSpace(row.DestinationWallet) != "" &&
		strings.TrimSpace(row.Amount) != "" && strings.TrimSpace(row.Asset) != "" && strings.TrimSpace(row.Program) != "" &&
		(row.VerificationStatus == "verified" || row.VerificationStatus == "observed")
}

func actorConstellationEvidenceSupports(classification string, evidence []ActorConstellationEvidenceRow) bool {
	if classification == "verified_counterparty_link" {
		for _, row := range evidence {
			if row.VerificationStatus == "verified" && actorConstellationEvidenceComplete(row) {
				return true
			}
		}
		return false
	}
	complete := 0
	for _, row := range evidence {
		if actorConstellationEvidenceComplete(row) {
			complete++
		}
	}
	return complete >= 2
}

var _ = time.Time{}
