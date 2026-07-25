package handlers

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"koschei/api/internal/services"
)

func actorDossierTestSnapshot(t *testing.T) dossierSnapshot {
	t.Helper()
	observed := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	wallet := "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe"
	evidence := []services.ActorDefenseEvidenceRecord{
		{
			Network: "solana-mainnet", ActorWallet: wallet, CounterpartKind: "token", CounterpartID: "Mint111",
			Relation: "created_token", VerificationStatus: "verified", EvidenceKey: "create:1", Source: "test",
			Signature: "CreateSig111", Slot: 101, ObservedAt: observed, TokenMint: "Mint111", OccurrenceCount: 1,
			Metadata: map[string]any{"source_wallet": wallet, "destination_wallet": "Mint111", "program": "pump.fun"},
		},
	}
	acceptance := services.EvaluateActorAcceptance(services.ActorAcceptanceInput{
		Wallet: wallet, Network: "solana-mainnet", TargetKind: "wallet",
		Dossier: services.ActorDefenseDossier{
			Wallet: wallet, Network: "solana-mainnet", Evidence: evidence,
			Tokens: []services.ActorDefenseTokenObservation{{Mint: "Mint111", Roles: []string{"creator_deployer"}}},
			Track: services.ActorDefenseTrack{Network: "solana-mainnet", TargetKind: "wallet", TargetID: wallet, CreatedTokenCount: 1},
		},
		FundingOrigin: services.ActorFundingOrigin{Status: "not_investigated", TrailStatus: "not_investigated"},
		Verdict: services.ActorDefenseRuleVerdict{
			Grade: "D", Verdict: "hard_trigger", RulesetVersion: services.ActorDefenseRulesetVersion,
			TriggeredRules: []services.ActorDefenseRuleHit{{RuleID: "ARD-H001", EvidenceStatus: "verified", EvidenceKeys: []string{"create:1"}}},
			Signed: true, Signature: "ActorVerdict111", DecisionPath: []string{"verified rule"},
		},
	})
	// The real case may legitimately contain failures/not-investigated states. The
	// export contract requires all ten states to remain visible, not all ten to pass.
	report := map[string]any{
		"ok": true,
		"schema_version": "koschei-unified-wallet-investigation-v1",
		"target": wallet,
		"wallet": wallet,
		"network": "solana-mainnet",
		"generated_at": observed.Format(time.RFC3339),
		"analysis_scope": "wallet_actor_investigation",
		"final_verdict": map[string]any{
			"grade": "D", "verdict": "hard_trigger", "signed": true,
			"signature": "UnifiedVerdict111", "ruleset_version": "koschei-unified-radar-rules-v1.0.0",
			"generated_at": observed.Format(time.RFC3339),
		},
		"actor_acceptance": acceptance,
		"actor_investigation": map[string]any{
			"wallet": wallet,
			"dossier": services.ActorDefenseDossier{
				Wallet: wallet, Network: "solana-mainnet", Evidence: evidence,
				Tokens: []services.ActorDefenseTokenObservation{{Mint: "Mint111", Roles: []string{"creator_deployer"}}},
				RelatedActors: []services.ActorDefenseRelatedActor{},
				Track: services.ActorDefenseTrack{Network: "solana-mainnet", TargetKind: "wallet", TargetID: wallet, CreatedTokenCount: 1},
			},
			"funding_origin": map[string]any{"status": "not_investigated", "verification_status": "unverified", "limitations": []string{"funding not investigated"}},
			"actor_live_evidence": map[string]any{"status": "partial", "limitations": []string{"bounded live window"}},
			"evidence_graph": map[string]any{"nodes": []any{}, "edges": []any{}},
		},
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return dossierSnapshot{
		ID: "22222222-2222-4222-8222-222222222222",
		Mint: wallet, Network: "solana-mainnet", VerdictSignature: dossierSnapshotIdentity(report, "UnifiedVerdict111"),
		RulesetVersion: "koschei-unified-radar-rules-v1.0.0", ProducedAt: observed,
		SourceHash: dossierSHA256(raw), Report: report,
	}
}

func TestAssembleActorDossierBundleIsDeterministicAndSelfContained(t *testing.T) {
	snapshot := actorDossierTestSnapshot(t)
	first, firstRaw, err := assembleDossierBundle(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	second, secondRaw, err := assembleDossierBundle(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstRaw) != string(secondRaw) || first.BundleHash != second.BundleHash {
		t.Fatal("identical actor snapshot produced different dossier identity")
	}
	target := dossierMap(first.Target)
	if dossierString(target["kind"]) != "wallet" || dossierString(target["id"]) != snapshot.Mint {
		t.Fatalf("unexpected actor target: %#v", target)
	}
	verification := dossierMap(first.Verification)
	if dossierString(verification["verdict_signature"]) != "UnifiedVerdict111" || dossierString(verification["snapshot_identity"]) != snapshot.VerdictSignature {
		t.Fatalf("verdict and snapshot identities were not separated: %#v", verification)
	}
	rows := dossierSlice(dossierMap(first.VerdictCard)["signal_rows"])
	if len(rows) != 10 {
		t.Fatalf("actor signal rows=%d", len(rows))
	}
	for index, raw := range rows {
		row := dossierMap(raw)
		expected := "AC-" + []string{"01", "02", "03", "04", "05", "06", "07", "08", "09", "10"}[index]
		if dossierString(row["id"]) != expected {
			t.Fatalf("row %d id=%q", index, dossierString(row["id"]))
		}
		if _, ok := row["limitations"].([]any); !ok {
			if _, typed := row["limitations"].([]string); !typed {
				t.Fatalf("row %s has no limitations array: %#v", expected, row)
			}
		}
	}
	if first.ActorAcceptance == nil || first.CreatedTokenHistory == nil || first.FundingOrigin == nil || first.CrossTokenConnections == nil || first.EvidenceLog == nil {
		t.Fatal("actor case is missing a self-contained section")
	}
	created := dossierSlice(first.CreatedTokenHistory)
	if len(created) != 1 || dossierString(dossierMap(created[0])["verification_status"]) != "verified" {
		t.Fatalf("created-token evidence status is missing: %#v", created)
	}
	sections := dossierMap(first.SectionLimitations)
	for _, key := range []string{"acceptance_items", "funding_origin", "created_token_history", "cross_token_connections", "evidence_log"} {
		if _, ok := sections[key]; !ok {
			t.Fatalf("section limitation %q missing", key)
		}
	}
	if !strings.Contains(dossierPretty(first.ActorAcceptance), "Direct creator → dominant-holder relation: NOT VERIFIED") {
		t.Fatal("explicit direct-relation withholding is missing")
	}
}

func TestActorSnapshotIdentityChangesWithAcceptanceEvidence(t *testing.T) {
	snapshot := actorDossierTestSnapshot(t)
	first := dossierSnapshotIdentity(snapshot.Report, "UnifiedVerdict111")
	acceptance := dossierMap(snapshot.Report["actor_acceptance"])
	acceptance["acceptance_hash"] = "sha256:" + strings.Repeat("f", 64)
	snapshot.Report["actor_acceptance"] = acceptance
	second := dossierSnapshotIdentity(snapshot.Report, "UnifiedVerdict111")
	if first == second {
		t.Fatal("acceptance change did not change immutable actor snapshot identity")
	}
	if !strings.HasPrefix(first, "actor-case:") || !strings.HasPrefix(second, "actor-case:") {
		t.Fatalf("unexpected actor snapshot identities: %q %q", first, second)
	}
}

func TestAssembleActorDossierRejectsMissingAcceptance(t *testing.T) {
	snapshot := actorDossierTestSnapshot(t)
	delete(snapshot.Report, "actor_acceptance")
	_, _, err := assembleDossierBundle(snapshot)
	if !errors.Is(err, errDossierAcceptanceMissing) {
		t.Fatalf("err=%v", err)
	}
}

func TestAssembleActorDossierRejectsVerifiedItemWithoutRefs(t *testing.T) {
	snapshot := actorDossierTestSnapshot(t)
	acceptance := dossierMap(snapshot.Report["actor_acceptance"])
	items := dossierSlice(acceptance["items"])
	first := dossierMap(items[0])
	first["evidence"] = []any{}
	first["evidence_state"] = "verified"
	items[0] = first
	acceptance["items"] = items
	snapshot.Report["actor_acceptance"] = acceptance
	_, _, err := assembleDossierBundle(snapshot)
	if !errors.Is(err, errDossierReferenceMissing) {
		t.Fatalf("err=%v", err)
	}
}
