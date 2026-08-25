package handlers

import "testing"

const piHandlerTestIssuer = "GAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCF6M"

func TestSecurityRadarInputIsPiByExplicitNetwork(t *testing.T) {
	for _, network := range []string{"pi", "pi-mainnet", "pi-testnet"} {
		if !securityRadarInputIsPi(securityRadarInput{Target: "not-yet-valid", Network: network}) {
			t.Fatalf("explicit Pi request %q was not routed to the Pi handler", network)
		}
	}
}

func TestSecurityRadarInputIsPiByAccountOrAssetTarget(t *testing.T) {
	for _, target := range []string{piHandlerTestIssuer, "KSAFE:" + piHandlerTestIssuer} {
		if !securityRadarInputIsPi(securityRadarInput{Target: target}) {
			t.Fatalf("Pi target %q was not auto-detected", target)
		}
	}
}

func TestSecurityRadarInputDoesNotStealSolanaTarget(t *testing.T) {
	if securityRadarInputIsPi(securityRadarInput{Target: "J4afsNkuv8JoZVdEd53Gmj9LAawhNsFfo8jY6GRjpump", Network: "solana-mainnet"}) {
		t.Fatal("Solana mint was incorrectly routed to the Pi handler")
	}
}
