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
			Entities:          []services.ActorResolvedEntity{},
			Relationships:     []services.ActorResolvedRelationship{},
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
	if !resolution.Available || resolution.RootEntity != "Actor111" || resolution.RelationshipCount != 1 {
		t.Fatalf("unexpected entity resolution projection: %#v", resolution)
	}
	policy, ok := envelope["evidence_policy"].(map[string]any)
	if !ok || policy["entity_resolution_is_not_identity_claim"] != true {
		t.Fatalf("entity-resolution claim boundary missing: %#v", envelope["evidence_policy"])
	}
}
