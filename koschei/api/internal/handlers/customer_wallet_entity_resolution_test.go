package handlers

import (
	"testing"

	"koschei/api/internal/services"
)

func TestCustomerWalletInvestigationEnvelopeExposesEntityResolution(t *testing.T) {
	result := customerWalletInvestigationResult{
		Target:  "Actor111",
		Wallet:  "Actor111",
		Network: "solana-mainnet",
		EntityResolution: services.ActorEntityResolution{
			Available:         true,
			RootEntity:        "Actor111",
			EntityCount:       2,
			RelationshipCount: 1,
			TransactionCount:  1,
			Entities:          []services.ActorResolvedEntity{},
			Relationships:     []services.ActorResolvedRelationship{},
			Transactions: []services.ActorResolvedTransaction{{
				Signature:          "Sig111",
				Slot:               42,
				Slots:              []int64{42},
				VerificationStatus: "verified",
			}},
			Policy: map[string]any{
				"identity_or_wrongdoing_claim": false,
			},
		},
	}

	envelope := customerWalletInvestigationEnvelope(result, false)
	resolution, ok := envelope["entity_resolution"].(services.ActorEntityResolution)
	if !ok {
		t.Fatalf("entity_resolution missing from customer envelope: %#v", envelope["entity_resolution"])
	}
	if !resolution.Available || resolution.RootEntity != "Actor111" || resolution.RelationshipCount != 1 || resolution.TransactionCount != 1 {
		t.Fatalf("unexpected entity resolution projection: %#v", resolution)
	}
	if len(resolution.Transactions) != 1 || resolution.Transactions[0].Signature != "Sig111" {
		t.Fatalf("transaction projection missing from customer envelope: %#v", resolution.Transactions)
	}
	policy, ok := envelope["evidence_policy"].(map[string]any)
	if !ok || policy["entity_resolution_is_not_identity_claim"] != true {
		t.Fatalf("entity-resolution claim boundary missing: %#v", envelope["evidence_policy"])
	}
}
