package services

import (
	"context"
	"net/http"
)

// enrichPiFundingClusterEvidenceFromHorizon reuses the bounded holder collector
// so funding provenance is based on actual trustline holders without bloating
// the base ARVIS arm contract with raw holder rows.
func enrichPiFundingClusterEvidenceFromHorizon(ctx context.Context, analysis ArvisAnalysis, target PiRadarTarget) ArvisAnalysis {
	if target.Kind != piRadarTargetKindAsset {
		return analysis
	}
	base, err := piHorizonBaseURL()
	if err != nil {
		observation := PiFundingClusterObservation{
			Status:                "provider_unavailable",
			EvidenceStatus:        "insufficient_evidence",
			Source:                piFundingEvidenceSource,
			Asset:                 target.AssetCode + ":" + target.Issuer,
			CandidateSetComplete:  false,
			HistoryWindowComplete: false,
			SharedSources:         []PiFundingSharedSourceGroup{},
			Rows:                  []PiFundingOriginRow{},
			Limitations:           []string{compactPiHorizonError(err)},
		}
		return applyPiFundingObservation(analysis, observation)
	}
	client := &http.Client{Timeout: piHorizonRequestTimeout}
	holders, pages, complete, holderErr := collectPiAssetHolders(ctx, client, base, target)
	observation := collectPiFundingClusterObservation(ctx, target, holders)
	if holderErr != nil {
		observation.CandidateSetComplete = false
		observation.HistoryWindowComplete = false
		observation.Limitations = append(observation.Limitations, "Holder candidate collection failed after "+itoaPiFunding(pages)+" page(s): "+compactPiHorizonError(holderErr))
	}
	if !complete {
		observation.CandidateSetComplete = false
		observation.Limitations = append(observation.Limitations, "Holder candidate pagination was bounded or incomplete; the funding cluster is not a complete holder-population claim.")
	}
	return applyPiFundingObservation(analysis, observation)
}

func applyPiFundingObservation(analysis ArvisAnalysis, observation PiFundingClusterObservation) ArvisAnalysis {
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

func itoaPiFunding(value int) string {
	if value == 0 {
		return "0"
	}
	const digits = "0123456789"
	var buf [20]byte
	index := len(buf)
	for value > 0 {
		index--
		buf[index] = digits[value%10]
		value /= 10
	}
	return string(buf[index:])
}
