package services

import "testing"

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
							"parsed": map[string]any{
								"type": "initializeMint2",
								"info": map[string]any{"mint": "Mint111"},
							},
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
						map[string]any{
							"programId": canonicalPumpFunProgramID,
							"type":      "create",
							"accounts":  []any{"PumpMint111", "Actor111"},
						},
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
							"parsed": map[string]any{
								"type": "initializeMint2",
								"info": map[string]any{"mint": "Token2022Mint111"},
							},
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
			t.Fatalf("invalid candidate: %#v", row)
		}
	}
}

func TestActorCreatedMintCandidateEvidenceNeverUpgradesDiscovery(t *testing.T) {
	evidence := ActorCreatedMintCandidateEvidence("Actor111", "solana-mainnet", []ActorCreatedMintCandidate{
		{
			Mint: "Mint111", Signature: "Sig111", Slot: 100,
			Program: canonicalPumpFunProgramID, ActorSigned: true,
			VerificationStatus: "observed", Source: "helius_get_transactions_for_address",
		},
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
