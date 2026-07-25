package handlers

import (
	"testing"

	"koschei/api/internal/services"
)

func TestActorAcceptanceHolderComparisonAvailable(t *testing.T) {
	for _, status := range []string{"verified_role_resolution", "dominant_holder_role_unresolved"} {
		if !actorAcceptanceHolderComparisonAvailable(status) {
			t.Fatalf("expected holder source %q to be accepted as completed", status)
		}
	}
	for _, status := range []string{"", "not_investigated", "largest_accounts_unavailable", "supply_unavailable", "token_account_owner_resolution_unavailable"} {
		if actorAcceptanceHolderComparisonAvailable(status) {
			t.Fatalf("unavailable holder source %q must not be treated as completed", status)
		}
	}
}

func TestActorAcceptanceDistributionCompleted(t *testing.T) {
	for _, status := range []string{"initial_recipients_resolved", "recipient_window_resolved", "no_creator_distribution_observed"} {
		if !actorAcceptanceDistributionCompleted(status) {
			t.Fatalf("expected distribution status %q to be terminal", status)
		}
	}
	for _, status := range []string{"", "not_investigated", "rpc_unavailable", "creator_token_accounts_not_observed", "invalid_target"} {
		if actorAcceptanceDistributionCompleted(status) {
			t.Fatalf("incomplete distribution status %q must not be terminal", status)
		}
	}
}

func TestActorAcceptanceTokenHasRoleIsExactAndCaseInsensitive(t *testing.T) {
	token := services.ActorDefenseTokenObservation{Roles: []string{"holder", "Creator_Deployer"}}
	if !actorAcceptanceTokenHasRole(token, "creator_deployer") {
		t.Fatal("creator role was not recognized")
	}
	if actorAcceptanceTokenHasRole(token, "creator") {
		t.Fatal("partial role match must not be accepted")
	}
}
