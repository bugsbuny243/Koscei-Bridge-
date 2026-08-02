package handlers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type ownerUnifiedRadarOverlay struct {
	Mode              string                              `json:"mode"`
	ManualOnly        bool                                `json:"manual_only"`
	AutomaticScanning bool                                `json:"automatic_scanning"`
	LegacyArmCount    int                                 `json:"legacy_arm_count"`
	CreatorWallet     string                              `json:"creator_wallet,omitempty"`
	ActorStatus       string                              `json:"actor_status"`
	ActorDossier      any                                 `json:"actor_dossier"`
	Behavior          services.UnifiedRadarBehaviorReport `json:"behavior_signals"`
	FinalVerdict      services.UnifiedRadarVerdict        `json:"final_verdict"`
	Narrative         string                              `json:"narrative"`
	Limitations       []string                            `json:"limitations"`
	GeneratedAt       time.Time                           `json:"generated_at"`
}

func (h *Handler) buildOwnerUnifiedRadarOverlay(ctx context.Context, target, network string, core holderIntelligenceCoreResult) ownerUnifiedRadarOverlay {
	now := time.Now().UTC()
	creator := strings.TrimSpace(fmt.Sprint(core.SourceContext["creator_wallet"]))
	if creator == "<nil>" {
		creator = ""
	}
	db := h.DBRead
	if db == nil {
		db = h.DB
	}

	sales := services.LoadCreatorSellAcceleration(ctx, db, target, creator, now)
	behavior := services.EvaluateUnifiedRadarBehavior(target, creator, core.Market, core.Intelligence, core.Cluster, sales, now)
	track := services.ActorDefenseTrack{Network: network, TargetKind: "token", TargetID: target, Dossier: map[string]any{}}
	actorEvidence := []services.ActorDefenseEvidenceRecord{}
	actorDossier := any(map[string]any{
		"available": false,
		"status":    "creator_or_database_unavailable",
		"wallet":    creator,
	})
	actorStatus := "unavailable"
	limitations := []string{}

	if creator == "" {
		limitations = append(limitations, "Creator/deployer wallet was not available; actor-memory rules were withheld while token-level behavior rules remained visible.")
	} else if db == nil {
		limitations = append(limitations, "Database was unavailable; persistent actor memory could not be joined to this manual token scan.")
	} else {
		store := services.NewActorDefenseStore(db)
		dossier, err := store.LoadPersistentWalletDossier(ctx, creator, network, 150)
		if err != nil {
			actorStatus = "load_failed"
			actorDossier = map[string]any{
				"available": false,
				"status":    "persistent_actor_dossier_load_failed",
				"wallet":    creator,
			}
			limitations = append(limitations, "Persistent actor dossier could not be loaded: "+compactUnifiedOverlayError(err))
		} else {
			actorStatus = "available"
			actorDossier = dossier
			track = dossier.Track
			// The signed unified verdict is token-scoped even when actor counters and
			// evidence come from the creator wallet's persistent dossier.
			track.TargetKind = "token"
			track.TargetID = target
			track.Network = network
			actorEvidence = dossier.Evidence
		}
	}

	actorVerdict := services.EvaluateActorDefenseRules(track, actorEvidence)
	unifiedVerdict := services.EvaluateUnifiedRadarVerdict(target, actorVerdict, behavior)
	return ownerUnifiedRadarOverlay{
		Mode:              "single_manual_radar",
		ManualOnly:        true,
		AutomaticScanning: false,
		LegacyArmCount:    14,
		CreatorWallet:     creator,
		ActorStatus:       actorStatus,
		ActorDossier:      actorDossier,
		Behavior:          behavior,
		FinalVerdict:      unifiedVerdict,
		Narrative:         ownerUnifiedRadarNarrative(unifiedVerdict),
		Limitations:       limitations,
		GeneratedAt:       now,
	}
}

func ownerUnifiedRadarNarrative(verdict services.UnifiedRadarVerdict) string {
	parts := []string{}
	if verdict.Grade == "-" {
		parts = append(parts, "Birleşik radar deterministik kurallarda harf notu oluşturacak kadar grade-değiştirici kanıt bulmadı; bu sonuç güvenli veya A notu anlamına gelmez.")
	} else {
		parts = append(parts, fmt.Sprintf("Birleşik radar verdict'i %s; karar %s ile deterministik olarak üretildi.", verdict.Grade, verdict.RulesetVersion))
	}
	for _, hit := range verdict.TriggeredRules {
		parts = append(parts, fmt.Sprintf("%s [%s, %s]: %s", hit.Title, hit.RuleID, strings.ToUpper(hit.EvidenceStatus), hit.Summary))
	}
	if len(verdict.WatchFlags) > 0 {
		parts = append(parts, fmt.Sprintf("%d watch flag görünür tutuldu ancak grade'i değiştirmedi.", len(verdict.WatchFlags)))
	}
	parts = append(parts, "AI notu seçmez; yalnızca tetiklenen kuralları açıklar.")
	return strings.Join(parts, " ")
}

func compactUnifiedOverlayError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.Join(strings.Fields(err.Error()), " ")
	if len(value) > 180 {
		value = value[:180]
	}
	return value
}
