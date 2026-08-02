package services

import (
	"math"
	"testing"
)

func TestHolderConcentrationCorpusFiftyThousandFixture(t *testing.T) {
	shares := make([]float64, 0, 50_000)
	for i := 0; i < 45_000; i++ {
		shares = append(shares, 10)
	}
	for i := 0; i < 2_500; i++ {
		shares = append(shares, 50)
	}
	for i := 0; i < 1_500; i++ {
		shares = append(shares, 70)
	}
	for i := 0; i < 1_000; i++ {
		shares = append(shares, 90)
	}

	counts := BuildHolderConcentrationHistogram(shares, 1)
	percentile, sampleCount, ok := HolderConcentrationTopPercentile(70, 1, counts)
	if !ok || sampleCount != 50_000 {
		t.Fatalf("ok=%t sample=%d", ok, sampleCount)
	}
	if percentile != 5 {
		t.Fatalf("70%% share percentile=%v, want top 5%%", percentile)
	}
	percentile, _, _ = HolderConcentrationTopPercentile(90, 1, counts)
	if percentile != 2 {
		t.Fatalf("90%% share percentile=%v, want top 2%%", percentile)
	}
}

func TestHolderConcentrationHistogramIgnoresInvalidShares(t *testing.T) {
	counts := BuildHolderConcentrationHistogram([]float64{-1, 0, 50, 100, 101, math.NaN(), math.Inf(1)}, 1)
	_, sampleCount, ok := HolderConcentrationTopPercentile(50, 1, counts)
	if !ok || sampleCount != 3 {
		t.Fatalf("ok=%t sample=%d counts=%v", ok, sampleCount, counts)
	}
}

func TestHolderConcentrationObservationRequiresResolvedRiskBearingOwner(t *testing.T) {
	holder := HolderIntelligence{
		Available: true, OwnerAggregationApplied: true, CirculatingSupply: 1_000_000, TopOwnerPercentage: 72,
		Rows: []HolderIntelligenceRow{{OwnerWallet: "Owner111", OwnerResolved: true, RiskBearing: true}},
	}
	wallet, share, ok := HolderConcentrationObservation(holder)
	if !ok || wallet != "Owner111" || share != 72 {
		t.Fatalf("wallet=%q share=%v ok=%t", wallet, share, ok)
	}

	holder.Rows[0].ExcludedFromHolderRisk = true
	if _, _, ok := HolderConcentrationObservation(holder); ok {
		t.Fatal("infrastructure-excluded owner entered corpus")
	}

	holder.Rows[0].ExcludedFromHolderRisk = false
	holder.Rows[0].OwnerResolved = false
	if _, _, ok := HolderConcentrationObservation(holder); ok {
		t.Fatal("unresolved owner entered corpus")
	}

	holder.Rows[0].OwnerResolved = true
	holder.OwnerAggregationApplied = false
	if _, _, ok := HolderConcentrationObservation(holder); ok {
		t.Fatal("raw token-account concentration entered corpus")
	}
}

func TestHolderConcentrationPercentileRejectsEmptyCorpus(t *testing.T) {
	if _, _, ok := HolderConcentrationTopPercentile(50, 1, nil); ok {
		t.Fatal("empty corpus returned percentile")
	}
}
