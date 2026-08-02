package handlers

import (
	"testing"

	"koschei/api/internal/services"
)

func TestRadarTargetWalletInvestigationAllowed(t *testing.T) {
	cases := []struct {
		name string
		in   radarTargetClassification
		want bool
	}{
		{name: "wallet", in: radarTargetClassification{Type: radarTargetWallet}, want: true},
		{name: "resolved token account", in: radarTargetClassification{Type: radarTargetTokenAccount, TokenOwnerWallet: "owner"}, want: true},
		{name: "unresolved token account", in: radarTargetClassification{Type: radarTargetTokenAccount}, want: false},
		{name: "mint", in: radarTargetClassification{Type: radarTargetTokenMint}, want: false},
		{name: "program", in: radarTargetClassification{Type: radarTargetProgram}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := radarTargetWalletInvestigationAllowed(tc.in); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestCustomerWalletInvestigationBoundedIsPublishedNotVerified(t *testing.T) {
	result := customerWalletInvestigationResult{
		FundingOrigin:   services.ActorFundingOrigin{ResultState: services.ActorFundingResultBounded},
		PublishedResult: true,
	}
	if status := customerWalletInvestigationStatus(result); status != "ready" {
		t.Fatalf("bounded result status=%q", status)
	}
	envelope := customerWalletInvestigationEnvelope(result, true)
	if envelope["published_result"] != true {
		t.Fatal("bounded result was not published")
	}
	policy, _ := envelope["evidence_policy"].(map[string]any)
	if policy["bounded_is_not_verified"] != true {
		t.Fatal("bounded policy was not explicit")
	}
	if _, exists := envelope["final_verdict"]; exists {
		t.Fatal("wallet envelope must not masquerade as a token final verdict")
	}
}

func TestCustomerWalletInvestigationMissingRemainsPending(t *testing.T) {
	result := customerWalletInvestigationResult{
		FundingOrigin: services.ActorFundingOrigin{ResultState: services.ActorFundingResultMissing},
	}
	if status := customerWalletInvestigationStatus(result); status != "evidence_pending" {
		t.Fatalf("missing result status=%q", status)
	}
}
