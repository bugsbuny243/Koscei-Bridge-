package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractActorCreatedMintCandidatesRequiresActorSigner(t *testing.T) {
	transactions := []map[string]any{
		{
			"slot": float64(123), "blockTime": float64(1700000000),
			"transaction": map[string]any{
				"signatures": []any{"SigCreate111"},
				"message": map[string]any{
					"accountKeys": []any{
						map[string]any{"pubkey": "Actor111", "signer": false},
						map[string]any{"pubkey": "OtherSigner111", "signer": true},
					},
					"instructions": []any{
						map[string]any{
							"programId": canonicalSPLTokenProgramID,
							"parsed":    map[string]any{"type": "initializeMint2", "info": map[string]any{"mint": "Mint111"}},
						},
					},
				},
			},
		},
	}
	if rows := ExtractActorCreatedMintCandidates(transactions, "Actor111", "fixture"); len(rows) != 0 {
		t.Fatalf("non-signer actor produced creator evidence: %#v", rows)
	}
}

func TestExtractActorCreatedMintCandidatesFindsPumpAndToken2022(t *testing.T) {
	transactions := []map[string]any{
		{
			"slot": float64(456), "blockTime": float64(1700000001),
			"transaction": map[string]any{
				"signatures": []any{"SigPump111"},
				"message": map[string]any{
					"accountKeys": []any{
						map[string]any{"pubkey": "Actor111", "signer": true},
						map[string]any{"pubkey": "PumpMint111", "signer": true},
					},
					"instructions": []any{
						map[string]any{"programId": canonicalPumpFunProgramID, "type": "create", "accounts": []any{"PumpMint111", "Actor111"}},
					},
				},
			},
		},
		{
			"slot": float64(455), "blockTime": float64(1700000000),
			"transaction": map[string]any{
				"signatures": []any{"SigToken2022111"},
				"message": map[string]any{
					"accountKeys": []any{map[string]any{"pubkey": "Actor111", "signer": true}},
					"instructions": []any{
						map[string]any{
							"programId": canonicalToken2022ProgramID,
							"parsed":    map[string]any{"type": "initializeMint2", "info": map[string]any{"mint": "Token2022Mint111"}},
						},
					},
				},
			},
		},
	}
	rows := ExtractActorCreatedMintCandidates(transactions, "Actor111", "fixture")
	if len(rows) != 2 {
		t.Fatalf("expected two created mint candidates, got %#v", rows)
	}
	if rows[0].Mint != "PumpMint111" || rows[1].Mint != "Token2022Mint111" {
		t.Fatalf("unexpected candidate ordering/content: %#v", rows)
	}
	for _, row := range rows {
		if row.VerificationStatus != "observed" || !row.ActorSigned || row.Signature == "" || row.Slot <= 0 {
			t.Fatalf("invalid external candidate: %#v", row)
		}
	}
}

func TestSolscanCreatedMintDiscoveryUsesEnhancedFiltersAndCursor(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/account/transactions/enhanced" {
			t.Fatalf("unexpected enhanced path: %s", r.URL.Path)
		}
		if r.Header.Get("token") != "test-key" {
			t.Fatal("missing Solscan API key header")
		}
		if r.URL.Query().Get("address") != "Actor111" || r.URL.Query().Get("encoding") != "jsonParsed" {
			t.Fatalf("missing actor filters: %s", r.URL.RawQuery)
		}
		if len(r.URL.Query()["program[]"]) != 3 || len(r.URL.Query()["signer[]"]) != 1 {
			t.Fatalf("missing server-side program/signer filters: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			payload := map[string]any{
				"success": true,
				"data": map[string]any{
					"cursor": "next-page",
					"transactions": []any{
						map[string]any{
							"slot": 100.0, "blockTime": 1700000000.0,
							"transaction": map[string]any{
								"signatures": []any{"Sig111"},
								"message": map[string]any{
									"accountKeys": []any{map[string]any{"pubkey": "Actor111", "signer": true}},
									"instructions": []any{map[string]any{
										"programId": canonicalSPLTokenProgramID,
										"parsed":    map[string]any{"type": "initializeMint", "info": map[string]any{"mint": "Mint111"}},
									}},
								},
							},
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(payload)
			return
		}
		if r.URL.Query().Get("cursor") != "next-page" {
			t.Fatalf("cursor was not propagated: %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"cursor": "", "transactions": []any{}}})
	}))
	defer server.Close()

	client := &SolscanClient{APIKey: "test-key", BaseURL: server.URL, Client: server.Client()}
	out := client.DiscoverCreatedMints(context.Background(), "Actor111")
	if !out.Available || out.Status != "complete" || out.PagesFetched != 2 {
		t.Fatalf("unexpected discovery coverage: %#v", out)
	}
	if len(out.Candidates) != 1 || out.Candidates[0].Mint != "Mint111" {
		t.Fatalf("created mint was not extracted: %#v", out.Candidates)
	}
}

func TestActorCreatedMintCandidateEvidenceNeverUpgradesExternalDiscovery(t *testing.T) {
	evidence := ActorCreatedMintCandidateEvidence("Actor111", "solana-mainnet", []ActorCreatedMintCandidate{
		{Mint: "Mint111", Signature: "Sig111", Slot: 100, Program: canonicalPumpFunProgramID, ActorSigned: true, VerificationStatus: "observed", Source: "solscan_enhanced_transactions"},
	})
	if len(evidence) != 1 {
		t.Fatalf("missing evidence: %#v", evidence)
	}
	if evidence[0].VerificationStatus != "observed" {
		t.Fatalf("external discovery was promoted: %#v", evidence[0])
	}
	if evidence[0].Metadata["actor_role"] != "creator_deployer" || evidence[0].Relation != "created_token" {
		t.Fatalf("creator memory contract missing: %#v", evidence[0])
	}
}
