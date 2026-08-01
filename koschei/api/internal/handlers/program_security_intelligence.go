package handlers

import (
	"context"
	"math"
	"strings"
	"time"

	"koschei/api/internal/defense"
	"koschei/api/internal/services"
)

const (
	programSecurityPumpFun  = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
	programSecurityPumpSwap = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"
)

type programSecurityCandidate struct {
	ProgramID string
	Role      string
}

type programAuthorityRPCAdapter struct {
	call solanaRPCCall
}

func (a programAuthorityRPCAdapter) Call(ctx context.Context, network, method string, params any, target any, ttl time.Duration) error {
	if ttl > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ttl)
		defer cancel()
	}
	return a.call(ctx, network, method, params, target)
}

func (h *Handler) collectProgramSecuritySurface(ctx context.Context, network string, source map[string]any, lp services.LPControlEvidence, market services.TokenMarketSnapshot) services.ProgramSecuritySurface {
	if h == nil {
		return newProgramSecuritySurface("rpc_unavailable")
	}
	return collectProgramSecuritySurface(ctx, h.lpRPC(), network, source, lp, market)
}

func collectProgramSecuritySurface(ctx context.Context, rpc solanaRPCCall, network string, source map[string]any, lp services.LPControlEvidence, market services.TokenMarketSnapshot) services.ProgramSecuritySurface {
	out := newProgramSecuritySurface("no_observed_program_candidates")
	candidates := programSecurityCandidates(source, lp, market)
	if len(candidates) == 0 {
		return out
	}
	if rpc == nil {
		out.Status = "rpc_unavailable"
		return out
	}
	adapter := programAuthorityRPCAdapter{call: rpc}
	authorityComplete := true
	ageComplete := true
	availableCount := 0
	for _, candidate := range candidates {
		item := services.ProgramSecurityEvidence{
			Role: candidate.Role, ProgramID: candidate.ProgramID,
			Status: "inspection_failed", AgeSemantics: "latest ProgramData deployment or upgrade age; not original program creation age",
			EvidenceRefs: []string{}, Limitations: []string{},
		}
		snapshot, err := defense.InspectProgramAuthority(ctx, adapter, defense.DeploymentResolveInput{ProgramID: candidate.ProgramID, Network: network})
		if err != nil {
			authorityComplete = false
			ageComplete = false
			item.Limitations = append(item.Limitations, compactCollectorError(err))
			out.Programs = append(out.Programs, item)
			continue
		}
		item.Available = true
		availableCount++
		item.Status = snapshot.Status
		item.LoaderID = snapshot.LoaderID
		item.LoaderKind = snapshot.LoaderKind
		item.ProgramDataAddress = snapshot.ProgramDataAddress
		item.AccountSlot = snapshot.AccountSlot
		item.DeploymentSlot = snapshot.DeploymentSlot
		item.UpgradeAuthority = snapshot.UpgradeAuthority
		item.UpgradeAuthorityOpen = snapshot.UpgradeAuthorityOpen
		item.Immutable = snapshot.Immutable
		item.EvidenceRefs = append(item.EvidenceRefs, snapshot.EvidenceRefs...)
		item.Limitations = append(item.Limitations, snapshot.Limitations...)
		if snapshot.DeploymentSlot > 0 {
			var blockTime *int64
			if blockErr := rpc(ctx, network, "getBlockTime", []any{snapshot.DeploymentSlot}, &blockTime); blockErr == nil && blockTime != nil && *blockTime > 0 {
				observed := time.Unix(*blockTime, 0).UTC()
				item.LastDeploymentAt = &observed
				if !observed.After(time.Now().UTC()) {
					item.AgeAvailable = true
					item.LastDeploymentAgeDays = math.Round(time.Since(observed).Hours()/24*100) / 100
				}
				item.EvidenceRefs = append(item.EvidenceRefs, "rpc:getBlockTime")
			} else {
				ageComplete = false
				item.Limitations = append(item.Limitations, "Deployment slot was verified but its block time was unavailable.")
			}
		} else {
			ageComplete = false
		}
		out.Programs = append(out.Programs, item)
	}
	out.Available = availableCount > 0
	out.AuthorityCoverageComplete = authorityComplete
	out.AgeCoverageComplete = ageComplete
	switch {
	case availableCount == 0:
		out.Status = "inspection_failed"
	case authorityComplete && ageComplete:
		out.Status = "complete"
	case authorityComplete:
		out.Status = "authority_complete_age_partial"
	default:
		out.Status = "partial"
	}
	return out
}

func newProgramSecuritySurface(status string) services.ProgramSecuritySurface {
	return services.ProgramSecuritySurface{
		Status: status, Programs: []services.ProgramSecurityEvidence{}, ObservedAt: time.Now().UTC(),
		EvidencePolicy: "upgrade authority is a capability fact, not proof of intent; age means latest deployment or upgrade age",
		Limitations:    []string{},
	}
}

func programSecurityCandidates(source map[string]any, lp services.LPControlEvidence, market services.TokenMarketSnapshot) []programSecurityCandidate {
	out := []programSecurityCandidate{}
	add := func(programID, role string) {
		programID = strings.TrimSpace(programID)
		if len(programID) < 32 || len(programID) > 44 {
			return
		}
		for _, existing := range out {
			if existing.ProgramID == programID {
				return
			}
		}
		if len(out) < 4 {
			out = append(out, programSecurityCandidate{ProgramID: programID, Role: role})
		}
	}
	add(lp.PoolProgram, "liquidity_pool_program")
	launchPlatform := strings.ToLower(strings.TrimSpace(creatorIntelCleanString(source["launch_platform"])))
	if strings.Contains(launchPlatform, "pump") {
		add(programSecurityPumpFun, "launch_program")
	}
	if strings.Contains(strings.ToLower(market.BestPairDEX), "pump") {
		add(programSecurityPumpSwap, "liquidity_pool_program")
	}
	if signals, ok := source["signals"].(map[string]any); ok {
		for _, key := range []string{"program_id", "program", "launch_program", "pool_program", "bonding_curve_program"} {
			add(creatorIntelCleanString(signals[key]), "source_observed_program")
		}
	}
	return out
}
