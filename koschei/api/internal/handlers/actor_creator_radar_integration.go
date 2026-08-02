package handlers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type actorCreatorRelationRun struct {
	Status      string                              `json:"status"`
	Target      services.ActorDistributionTarget    `json:"target"`
	Evidence    services.ActorDefenseEvidenceRecord `json:"evidence"`
	Persistence string                              `json:"persistence"`
	Limitations []string                            `json:"limitations"`
}

type actorDistributionIntegrationRun struct {
	Status              string                               `json:"status"`
	Target              services.ActorDistributionTarget     `json:"target"`
	Report              services.ActorInitialRecipientReport `json:"report"`
	EvidenceProduced    int                                  `json:"evidence_produced"`
	EvidencePersisted   int                                  `json:"evidence_persisted"`
	PersistenceFailures int                                  `json:"persistence_failures"`
	Limitations         []string                             `json:"limitations"`
}

func newActorCreatorRelationRun(creator, mint string) actorCreatorRelationRun {
	return actorCreatorRelationRun{
		Status: "not_requested",
		Target: services.ActorDistributionTarget{
			CreatorWallet: strings.TrimSpace(creator), Mint: strings.TrimSpace(mint),
			VerificationStatus: "unverified",
		},
		Evidence:    services.ActorDefenseEvidenceRecord{Metadata: map[string]any{}},
		Persistence: "not_requested", Limitations: []string{},
	}
}

func newActorDistributionIntegrationRun(creator, mint string) actorDistributionIntegrationRun {
	return actorDistributionIntegrationRun{
		Status: "not_requested",
		Target: services.ActorDistributionTarget{
			CreatorWallet: strings.TrimSpace(creator), Mint: strings.TrimSpace(mint),
			VerificationStatus: "unverified",
		},
		Report: services.ActorInitialRecipientReport{
			CreatorWallet: strings.TrimSpace(creator), Mint: strings.TrimSpace(mint),
			Status: "not_requested", DistributionScope: "not_requested",
			SourceTokenAccounts: []string{}, Recipients: []services.ActorInitialRecipient{},
			TopHolderStatus: "not_requested", Limitations: []string{},
		},
		Limitations: []string{},
	}
}

// persistCanonicalCreatorMintRelation converts the creator relation already
// discovered by the canonical token radar into persistent actor memory. A launch
// source observation is VERIFIED only when the source marks the relation verified
// and provides both a signature and slot; otherwise it remains OBSERVED.
func (h *Handler) persistCanonicalCreatorMintRelation(ctx context.Context, store *services.ActorDefenseStore, core holderIntelligenceCoreResult, creator, network string) actorCreatorRelationRun {
	mint := strings.TrimSpace(core.Request.Target)
	creator = strings.TrimSpace(creator)
	out := newActorCreatorRelationRun(creator, mint)
	if creator == "" || mint == "" {
		out.Status = "target_unavailable"
		out.Limitations = append(out.Limitations, "Creator wallet veya token mint çözümlenemedi.")
		return out
	}
	if store == nil || store.DB == nil {
		out.Status = "persistence_unavailable"
		out.Limitations = append(out.Limitations, "Actor evidence store kullanılamıyor.")
		return out
	}

	source := core.SourceContext
	signature := strings.TrimSpace(firstNonEmptyString(
		creatorIntelCleanString(source["signature"]),
		creatorIntelCleanString(source["creation_signature"]),
		creatorIntelCleanString(source["launch_signature"]),
	))
	slot := creatorIntelInt64(source["slot"])
	observedAt := time.Now().UTC()
	if value := strings.TrimSpace(creatorIntelCleanString(source["observed_at"])); value != "" {
		if parsed, err := time.Parse(time.RFC3339, value); err == nil {
			observedAt = parsed.UTC()
		}
	}

	// Older source-context projections omitted slot. Recover the canonical event
	// fields directly from the radar ledger before deciding the evidence class.
	if signature == "" || slot <= 0 {
		var eventSignature string
		var eventSlot int64
		var eventObservedAt time.Time
		err := store.DB.QueryRowContext(ctx, `
			SELECT COALESCE(signature,''),COALESCE(slot,0),created_at
			FROM security_radar_events
			WHERE network=$1 AND lower(target)=lower($2)
			  AND (
				COALESCE(signals->>'creator_wallet','')=$3 OR
				COALESCE(signals->>'deployer_wallet','')=$3 OR
				(source='pumpportal' AND source_address=$3)
			  )
			ORDER BY
			  CASE WHEN event_type='pumpportal_high_volume_24h' THEN 0 WHEN source='pumpportal' THEN 1 ELSE 2 END,
			  created_at DESC
			LIMIT 1`, network, mint, creator).Scan(&eventSignature, &eventSlot, &eventObservedAt)
		if err == nil {
			if signature == "" {
				signature = strings.TrimSpace(eventSignature)
			}
			if slot <= 0 {
				slot = eventSlot
			}
			if !eventObservedAt.IsZero() {
				observedAt = eventObservedAt.UTC()
			}
		}
	}

	verifiedFlag, _ := source["creator_relation_verified"].(bool)
	verificationStatus := "observed"
	if verifiedFlag && signature != "" && slot > 0 {
		verificationStatus = "verified"
	}
	program := strings.TrimSpace(firstNonEmptyString(
		creatorIntelCleanString(source["launch_platform"]),
		creatorIntelCleanString(source["program"]),
	))
	if program == "" {
		program = "pump.fun"
	}
	evidenceSource := strings.TrimSpace(creatorIntelCleanString(source["source"]))
	if evidenceSource == "" {
		evidenceSource = "canonical_token_radar"
	}

	item := services.ActorDefenseEvidenceRecord{
		Network: network, ActorWallet: creator,
		CounterpartKind: "token", CounterpartID: mint,
		Relation: "created_token", VerificationStatus: verificationStatus,
		EvidenceKey: "canonical_creator_relation:" + mint,
		Source:      evidenceSource, Signature: signature, Slot: slot, ObservedAt: observedAt,
		TokenMint: mint, OccurrenceCount: 1,
		Metadata: map[string]any{
			"actor_role":                     "creator_deployer",
			"source_wallet":                  creator,
			"destination_wallet":             mint,
			"program":                        program,
			"creator_relation_verified_flag": verifiedFlag,
			"creator_relation_scope":         creatorIntelCleanString(source["creator_scope"]),
			"source_event_type":              creatorIntelCleanString(source["event_type"]),
			"source_module_id":               creatorIntelCleanString(source["module_id"]),
			"persistent_actor_index":         true,
			"identity_or_wrongdoing_claim":   false,
		},
	}
	out.Evidence = item
	out.Target = services.ActorDistributionTarget{
		CreatorWallet: creator, Mint: mint, CreationSignature: signature,
		VerificationStatus: verificationStatus, FirstObservedAt: observedAt, LastObservedAt: observedAt,
	}
	out.Persistence = "persisted"
	if err := store.UpsertEvidence(ctx, item); err != nil {
		out.Status = "persistence_failed"
		out.Persistence = "failed"
		out.Limitations = append(out.Limitations, "Creator → mint kanıtı actor index'e yazılamadı: "+creatorIntelCompactError(err))
		return out
	}
	out.Status = verificationStatus
	if verificationStatus != "verified" {
		gaps := []string{}
		if !verifiedFlag {
			gaps = append(gaps, "verified_source_flag")
		}
		if signature == "" {
			gaps = append(gaps, "signature")
		}
		if slot <= 0 {
			gaps = append(gaps, "slot")
		}
		out.Limitations = append(out.Limitations, "Creator → mint ilişkisi OBSERVED kaldı; eksik doğrulama alanları: "+strings.Join(gaps, ", ")+".")
	}
	return out
}

// collectCanonicalActorDistribution runs the existing mint-specific ATA
// investigator for the current token. It never crawls recipient-wide histories.
func (h *Handler) collectCanonicalActorDistribution(ctx context.Context, store *services.ActorDefenseStore, relation actorCreatorRelationRun, network string) actorDistributionIntegrationRun {
	out := newActorDistributionIntegrationRun(relation.Target.CreatorWallet, relation.Target.Mint)
	out.Target = relation.Target
	if store == nil {
		out.Status = "persistence_unavailable"
		out.Limitations = append(out.Limitations, "Actor evidence store kullanılamıyor.")
		return out
	}
	if relation.Persistence != "persisted" {
		out.Status = "creator_mint_relation_unavailable"
		out.Limitations = append(out.Limitations, "Creator → mint ilişkisi kalıcı actor index'e yazılmadığı için dağıtım araştırması başlatılmadı.")
		return out
	}

	timeout := time.Duration(actorDefenseEnvInt("ACTOR_RECIPIENT_TIMEOUT_SECONDS", 150, 30, 240)) * time.Second
	distributionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	target, err := store.ResolvePersistentCreatorMint(distributionCtx, relation.Target.CreatorWallet, relation.Target.Mint, network)
	if err != nil {
		out.Status = "creator_mint_relation_unresolved"
		out.Limitations = append(out.Limitations, creatorIntelCompactError(err))
		return out
	}
	out.Target = target
	out.Report = services.InvestigateActorInitialRecipients(
		distributionCtx,
		creatorIntelRPCURL(),
		target.CreatorWallet,
		target.Mint,
		target.CreationSignature,
		services.ActorInitialRecipientOptions{
			MaxRecipients:        actorDefenseEnvInt("ACTOR_RECIPIENT_LIMIT", 20, 1, 20),
			SignaturePageSize:    actorDefenseEnvInt("ACTOR_RECIPIENT_SIGNATURE_PAGE_SIZE", 250, 50, 1000),
			MaxPagesPerTokenATA:  actorDefenseEnvInt("ACTOR_RECIPIENT_MAX_PAGES_PER_ATA", 8, 1, 20),
			MaxTransactionsParse: actorDefenseEnvInt("ACTOR_RECIPIENT_TRANSACTION_LIMIT", 160, 10, 500),
		},
	)
	out.Status = out.Report.Status
	out.Limitations = append(out.Limitations, out.Report.Limitations...)
	evidence := services.ActorInitialRecipientEvidence(out.Report, network)
	out.EvidenceProduced = len(evidence)
	for _, item := range evidence {
		if err := store.UpsertEvidence(distributionCtx, item); err != nil {
			out.PersistenceFailures++
			continue
		}
		out.EvidencePersisted++
	}
	if out.PersistenceFailures > 0 {
		out.Status = "partial_persistence"
		out.Limitations = append(out.Limitations, fmt.Sprintf("%d dağıtım kanıtı actor index'e yazılamadı.", out.PersistenceFailures))
	}
	return out
}
