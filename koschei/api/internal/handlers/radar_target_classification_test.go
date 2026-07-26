package handlers

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"koschei/api/internal/defense"
	"koschei/api/internal/services"
)

func TestClassifyRadarAccountObservationSeparatesSolanaTargetKinds(t *testing.T) {
	tests := []struct {
		name               string
		account            *services.SolanaAccountInfo
		wantType           string
		wantLoaderState    string
		wantTokenOwner     string
		wantVerdictAllowed bool
	}{
		{
			name: "token mint",
			account: &services.SolanaAccountInfo{Owner: "Tokenkeg", Data: map[string]any{
				"parsed": map[string]any{"type": "mint", "info": map[string]any{}},
			}},
			wantType: radarTargetTokenMint, wantVerdictAllowed: true,
		},
		{
			name: "token account",
			account: &services.SolanaAccountInfo{Owner: "Tokenkeg", Data: map[string]any{
				"parsed": map[string]any{"type": "account", "info": map[string]any{"owner": "Holder111"}},
			}},
			wantType: radarTargetTokenAccount, wantTokenOwner: "Holder111",
		},
		{
			name: "executable program",
			account: &services.SolanaAccountInfo{Owner: defense.UpgradeableLoaderID, Executable: true},
			wantType: radarTargetProgram,
		},
		{
			name: "program data",
			account: &services.SolanaAccountInfo{Owner: defense.UpgradeableLoaderID, Data: loaderStateData(3)},
			wantType: radarTargetProgramData, wantLoaderState: "program_data",
		},
		{
			name: "program buffer",
			account: &services.SolanaAccountInfo{Owner: defense.UpgradeableLoaderID, Data: loaderStateData(1)},
			wantType: radarTargetProgramBuffer, wantLoaderState: "buffer",
		},
		{
			name: "unresolved loader account fails closed",
			account: &services.SolanaAccountInfo{Owner: defense.UpgradeableLoaderID, Data: []any{"not-base64", "base64"}},
			wantType: radarTargetProgramLoaderAccount,
		},
		{
			name: "wallet",
			account: &services.SolanaAccountInfo{Owner: "11111111111111111111111111111111", Executable: false},
			wantType: radarTargetWallet,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := classifyRadarAccountObservation(test.account)
			if got.Type != test.wantType {
				t.Fatalf("type=%q want=%q classification=%+v", got.Type, test.wantType, got)
			}
			if got.Status != "verified_rpc_observation" {
				t.Fatalf("status=%q classification=%+v", got.Status, got)
			}
			if got.LoaderState != test.wantLoaderState {
				t.Fatalf("loader_state=%q want=%q", got.LoaderState, test.wantLoaderState)
			}
			if got.TokenOwnerWallet != test.wantTokenOwner {
				t.Fatalf("token_owner_wallet=%q want=%q", got.TokenOwnerWallet, test.wantTokenOwner)
			}
			if allowed := radarTargetTokenVerdictAllowed(got); allowed != test.wantVerdictAllowed {
				t.Fatalf("verdict_allowed=%v want=%v classification=%+v", allowed, test.wantVerdictAllowed, got)
			}
		})
	}
}

func TestClassifyRadarAccountObservationNilFailsClosed(t *testing.T) {
	got := classifyRadarAccountObservation(nil)
	if got.Type != radarTargetUnknown || got.Status != "account_not_found" {
		t.Fatalf("unexpected nil classification: %+v", got)
	}
	if radarTargetTokenVerdictAllowed(got) {
		t.Fatal("missing account must never receive a token verdict")
	}
}

func TestRadarUpgradeableLoaderStateRejectsUnknownOrMalformedData(t *testing.T) {
	if got := radarUpgradeableLoaderState(loaderStateData(99)); got != "" {
		t.Fatalf("unknown loader state accepted: %q", got)
	}
	if got := radarUpgradeableLoaderState([]any{"%%%", "base64"}); got != "" {
		t.Fatalf("malformed loader data accepted: %q", got)
	}
	if got := radarUpgradeableLoaderState(map[string]any{"parsed": map[string]any{"type": "mint"}}); got != "" {
		t.Fatalf("parsed token data accepted as loader state: %q", got)
	}
}

func TestRadarTargetRejectionMessagesRouteProgramArtifactsToDefense(t *testing.T) {
	for _, targetType := range []string{radarTargetProgram, radarTargetProgramData, radarTargetProgramBuffer, radarTargetProgramLoaderAccount} {
		message := radarTargetRejectionMessage(radarTargetClassification{Type: targetType})
		if strings.Contains(strings.ToLower(message), "wallet intelligence") {
			t.Fatalf("program artifact %q was routed to wallet intelligence: %q", targetType, message)
		}
		if !strings.Contains(message, "Token risk skoru uygulanamaz") {
			t.Fatalf("program artifact %q lacks token-verdict rejection: %q", targetType, message)
		}
	}
}

func loaderStateData(state uint32) []any {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, state)
	return []any{base64.StdEncoding.EncodeToString(data), "base64"}
}
