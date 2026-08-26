package handlers

import (
	"testing"

	"koschei/api/internal/services"
)

func TestHolderClusterAttackPathEvidenceReferenceUsesConcreteFlowEvidence(t *testing.T) {
	cluster := services.HolderClusterAnalysis{
		Available:           true,
		SynchronizedWallets: []string{"Sync111", "Sync222"},
		SharedFundingGroups: []services.HolderClusterGroup{{Key: "Funder111", Wallets: []string{"Holder111", "Holder222"}}},
		Wallets: []services.HolderClusterWallet{
			{
				Wallet:          "Holder111",
				AcquisitionSlot: 100,
				FlowObservations: []services.HolderClusterFlowObservation{
					{
						SourceWallet:            "Holder111",
						Destination:             "Exit111",
						SourceTokenAccount:      "SourceATA111",
						DestinationTokenAccount: "ExitATA111",
						Signature:               "ExitSig111",
						Slot:                    200,
					},
				},
			},
		},
	}

	ref := holderClusterAttackPathEvidenceReference(cluster)
	assertContainsString(t, ref.Wallets, "Holder111")
	assertContainsString(t, ref.Wallets, "Funder111")
	assertContainsString(t, ref.Wallets, "Exit111")
	assertContainsString(t, ref.Wallets, "Sync111")
	assertContainsString(t, ref.Accounts, "SourceATA111")
	assertContainsString(t, ref.Accounts, "ExitATA111")
	assertContainsString(t, ref.Signatures, "ExitSig111")
	assertContainsInt64(t, ref.Slots, 100)
	assertContainsInt64(t, ref.Slots, 200)
}

func TestAttackPathProjectionLinksCoordinatedExitOnlyFromTypedAvailableCluster(t *testing.T) {
	threat := services.ThreatAnticipationReport{
		Target: "Mint111",
		Status: "evidence_backed_pathway_analysis",
		Pathways: []services.ThreatPathway{{
			ID: "coordinated_holder_exit", Status: "observed", EvidenceStatus: "observed",
		}},
	}
	cluster := services.HolderClusterAnalysis{
		Available: true,
		Flow: services.HolderClusterFlowAnalysis{
			Available: true,
			Observations: []services.HolderClusterFlowObservation{{
				SourceWallet: "Holder111", Destination: "CommonExit111", Signature: "CommonExitSig111", Slot: 555,
			}},
		},
	}

	projection, ok := attackPathProjectionFromReport(map[string]any{
		"threat_anticipation": threat,
		"holder_cluster":      cluster,
	})
	if !ok {
		t.Fatal("expected typed attack path projection")
	}
	linked, ok := projection["evidence_references"].(map[string]unifiedEvidenceReference)
	if !ok {
		t.Fatalf("expected coordinated-exit evidence links, got %#v", projection["evidence_references"])
	}
	ref, exists := linked["coordinated_holder_exit"]
	if !exists {
		t.Fatal("coordinated holder exit evidence was not linked")
	}
	assertContainsString(t, ref.Wallets, "Holder111")
	assertContainsString(t, ref.Wallets, "CommonExit111")
	assertContainsString(t, ref.Signatures, "CommonExitSig111")
	assertContainsInt64(t, ref.Slots, 555)

	unavailable, ok := attackPathProjectionFromReport(map[string]any{
		"threat_anticipation": threat,
		"holder_cluster":      services.HolderClusterAnalysis{Available: false, Wallets: []services.HolderClusterWallet{{Wallet: "Fake111"}}},
	})
	if !ok {
		t.Fatal("expected typed attack path projection for unavailable cluster")
	}
	if _, exists := unavailable["evidence_references"]; exists {
		t.Fatalf("unavailable holder cluster must not produce attack-path evidence: %#v", unavailable["evidence_references"])
	}
}
