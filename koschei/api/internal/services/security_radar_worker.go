package services

import (
	"context"
	"log"
	"strings"
	"time"
)

type SecurityRadarWorker struct {
	Store     *SecurityRadarStore
	SolanaRPC string
	PollEvery time.Duration
	Enabled   bool
}

func NewSecurityRadarWorker(store *SecurityRadarStore, solanaRPC string, enabled bool, pollEvery time.Duration) *SecurityRadarWorker {
	if pollEvery < 30*time.Second {
		pollEvery = 60 * time.Second
	}
	return &SecurityRadarWorker{Store: store, SolanaRPC: strings.TrimSpace(solanaRPC), Enabled: enabled, PollEvery: pollEvery}
}

func (w *SecurityRadarWorker) Start(ctx context.Context) {
	if w == nil || !w.Enabled {
		return
	}
	if strings.TrimSpace(w.SolanaRPC) == "" {
		log.Printf("security radar worker disabled: SOLANA_RPC_URL is empty")
		return
	}
	if w.Store == nil || w.Store.DB == nil {
		log.Printf("security radar worker disabled: store database is nil")
		return
	}
	log.Printf("security radar worker started provider=%s mode=%s interval=%s", providerFromSolanaRPCURL(w.SolanaRPC), SecurityRadarWatchMode, w.PollEvery)
	if err := w.PollOnce(ctx); err != nil {
		log.Printf("security radar poll failed: %s", safeProviderError(err))
	}
	ticker := time.NewTicker(w.PollEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("security radar worker stopped")
			return
		case <-ticker.C:
			if err := w.PollOnce(ctx); err != nil {
				log.Printf("security radar poll failed: %s", safeProviderError(err))
			}
		}
	}
}

func (w *SecurityRadarWorker) PollOnce(ctx context.Context) error {
	if w == nil || w.Store == nil || w.Store.DB == nil || strings.TrimSpace(w.SolanaRPC) == "" {
		return nil
	}
	sources, err := w.Store.EnabledSources(ctx)
	if err != nil {
		return err
	}
	if len(sources) == 0 {
		log.Printf("security radar worker waiting for verified sources")
		return nil
	}
	for _, source := range sources {
		if err := w.pollSource(ctx, source); err != nil {
			log.Printf("security radar source poll failed module=%s address=%s err=%s", source.ModuleID, source.Address, safeProviderError(err))
		}
	}
	return nil
}

func (w *SecurityRadarWorker) pollSource(ctx context.Context, source SecurityRadarSource) error {
	pollCtx, cancel := context.WithTimeout(ctx, minSecurityRadarDuration(w.PollEvery, 12*time.Second))
	defer cancel()
	provider := providerFromSolanaRPCURL(w.SolanaRPC)
	provenance := provider + "_polling"
	signatures, err := SolanaGetSignaturesForAddress(pollCtx, w.SolanaRPC, source.Address, 10)
	if err != nil {
		return err
	}
	for i := len(signatures) - 1; i >= 0; i-- {
		info := signatures[i]
		sig := strings.TrimSpace(info.Signature)
		if sig == "" {
			continue
		}
		inserted, err := w.Store.MarkSignatureSeen(ctx, source.ModuleID, sig, source.Address, source.Network)
		if err != nil {
			return err
		}
		if !inserted {
			continue
		}
		var blockTime *time.Time
		if info.BlockTime != nil && *info.BlockTime > 0 {
			t := time.Unix(*info.BlockTime, 0).UTC()
			blockTime = &t
		}
		eventID, err := w.Store.InsertEvent(ctx, SecurityRadarEventRecord{
			ModuleID:      source.ModuleID,
			Target:        source.Address,
			TargetType:    "program",
			Network:       source.Network,
			Signature:     sig,
			SourceAddress: source.Address,
			EventType:     "solana_signature",
			Slot:          info.Slot,
			BlockTime:     blockTime,
			Source:        provenance,
			Signals: map[string]any{
				"signature":    sig,
				"slot":         info.Slot,
				"rpc_method":   "getSignaturesForAddress",
				"source":       source.Label,
				"rpc_provider": provider,
				"provenance":   provenance,
			},
			RawSummary: map[string]any{
				"signature": sig,
				"slot":      info.Slot,
				"err":       info.Err,
			},
		})
		if err != nil {
			return err
		}
		analysis := AnalyzeArvisRadarsContext(pollCtx, SecurityRadarRequest{
			Target: source.Address, Network: source.Network, Mode: "live_stream:" + source.ModuleID,
		})
		verdict := securityRadarModuleVerdict(analysis.Bundle, source.ModuleID)
		_, err = w.Store.InsertVerdict(ctx, SecurityRadarVerdictRecord{
			EventID:        eventID,
			ModuleID:       verdict.ModuleID,
			Target:         verdict.Target,
			TargetType:     "program",
			Network:        verdict.Network,
			Grade:          verdict.Grade,
			RiskIndex:      verdict.RiskIndex,
			RiskLevel:      verdict.RiskLevel,
			Verdict:        verdict.Verdict,
			Recommendation: verdict.Recommendation,
			Evidence:       verdict.Evidence,
			Signals:        verdict.Signals,
			RuleVersion:    verdict.RuleVersion,
			Signed:         verdict.Signed,
			Signature:      verdict.Signature,
			Source:         provenance,
			Provider:       provider,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func securityRadarModuleVerdict(bundle SecurityRadarBundle, moduleID string) SecurityRadarVerdict {
	switch moduleID {
	case ModuleRaydiumPoolGuardian:
		return bundle.RaydiumPoolGuardian
	case ModuleWalletlessClaimShield:
		return bundle.WalletlessClaimShield
	default:
		return bundle.PumpSybilRadar
	}
}

func isSecurityRadarMissingRelation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "does not exist") || strings.Contains(msg, "undefined_table") || strings.Contains(msg, "42p01")
}

func minSecurityRadarDuration(a, b time.Duration) time.Duration {
	if a > 0 && a < b {
		return a
	}
	return b
}
