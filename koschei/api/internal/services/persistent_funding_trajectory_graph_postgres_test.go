package services

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestPersistentFundingTrajectoryGraphPostgres17(t *testing.T) {
	databaseURL := os.Getenv("KOSCHEI_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KOSCHEI_TEST_DATABASE_URL is not set")
	}
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	nonce := time.Now().UTC().UnixNano()
	network := "solana-mainnet"
	funder := fmt.Sprintf("TrajectoryFunder%d", nonce)
	creator := fmt.Sprintf("TrajectoryCreator%d", nonce)
	mint := fmt.Sprintf("TrajectoryToken%d", nonce)
	fundingSignature := fmt.Sprintf("trajectory-funding-%d", nonce)
	creationSignature := fmt.Sprintf("trajectory-creation-%d", nonce)
	verdictSignature := fmt.Sprintf("trajectory-verdict-%d", nonce)
	verdictFingerprint := fmt.Sprintf("trajectory-fingerprint-%d", nonce)
	exitSignature := fmt.Sprintf("trajectory-exit-%d", nonce)
	baseTime := time.Now().UTC().Add(-72 * time.Hour)

	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM security_actor_exit_events WHERE network=$1 AND actor_wallet=$2`, network, creator)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM security_unified_radar_verdicts WHERE network=$1 AND target_id=$2`, network, mint)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM security_actor_token_lifecycle WHERE network=$1 AND actor_wallet=$2 AND mint=$3`, network, creator, mint)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM security_actor_evidence WHERE network=$1 AND (actor_wallet=$2 OR counterpart_id=$3)`, network, creator, funder)
	}()

	store := NewActorDefenseStore(db)
	if err := store.UpsertEvidence(ctx, ActorDefenseEvidenceRecord{
		Network: network, ActorWallet: creator,
		CounterpartKind: "wallet", CounterpartID: funder,
		Relation: "initial_funding_in", VerificationStatus: "verified",
		EvidenceKey: fundingSignature + ":initial_funding", Source: "trajectory_test",
		Signature: fundingSignature, Slot: 1101, ObservedAt: baseTime,
		Metadata: map[string]any{
			"actor_role": "funded_wallet", "source_wallet": funder,
			"destination_wallet": creator, "history_complete": true,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertEvidence(ctx, ActorDefenseEvidenceRecord{
		Network: network, ActorWallet: creator,
		CounterpartKind: "token", CounterpartID: mint, TokenMint: mint,
		Relation: "created_token", VerificationStatus: "verified",
		EvidenceKey: creationSignature + ":created_token", Source: "trajectory_test",
		Signature: creationSignature, Slot: 1201, ObservedAt: baseTime.Add(4 * time.Hour),
		Metadata: map[string]any{
			"actor_role": "creator_deployer", "persistent_actor_index": true,
		},
	}); err != nil {
		t.Fatal(err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO security_actor_token_lifecycle
		(network,actor_wallet,mint,creation_signature,creation_slot,created_on_chain_at,
		 first_observed_at,last_observed_at,first_liquid_observed_at,last_liquid_observed_at,
		 first_inactive_observed_at,current_inactive_since,current_liquidity_usd,current_price_usd,
		 fate_status,observation_count,reactivation_count)
		VALUES
		($1,$2,$3,$4,1201,$5,$6,$7,$6,$8,$9,$9,0,0,'inactive_or_dead',7,0)`,
		network, creator, mint, creationSignature,
		baseTime.Add(4*time.Hour), baseTime.Add(5*time.Hour), baseTime.Add(36*time.Hour),
		baseTime.Add(20*time.Hour), baseTime.Add(30*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO security_unified_radar_verdicts
		(network,target_kind,target_id,grade,verdict,ruleset_version,actor_ruleset_version,signed,signature,fingerprint,first_seen_at,last_seen_at)
		VALUES
		($1,'token',$2,'C','compounding_rule','rules-v1','actor-rules-v1',true,$3,$4,$5,$5)`,
		network, mint, verdictSignature, verdictFingerprint, baseTime.Add(40*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO security_actor_exit_events
		(actor_wallet,network,target,event_kind,evidence_state,signature,slot,observed_at,source_rule_id,detail)
		VALUES
		($1,$2,$3,'liquidity_removal','verified',$4,1301,$5,'TEST-TRAJECTORY-EXIT','{}'::jsonb)`,
		creator, network, mint, exitSignature, baseTime.Add(44*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	graph, err := LoadPersistentFundingTrajectoryGraph(ctx, db, creator, network, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !graph.Available || !graph.Complete || graph.Status != "persistent_trajectory_observed" {
		t.Fatalf("unexpected graph status: %+v", graph)
	}
	if graph.NodeCount != 4 {
		t.Fatalf("expected funder + creator + token + verdict nodes, got %+v", graph.Nodes)
	}
	if graph.EdgeCount != 5 || graph.FundingEdgeCount != 1 || graph.CreationEdgeCount != 1 || graph.LifecycleEdgeCount != 1 || graph.SignedVerdictEdgeCount != 1 || graph.ExitEdgeCount != 1 {
		t.Fatalf("unexpected trajectory edge counts: %+v", graph)
	}
	if graph.VerifiedEvidenceEdgeCount != 4 || graph.SignedArtifactEdgeCount != 1 || graph.ObservedEvidenceEdgeCount != 0 {
		t.Fatalf("unexpected evidence-state counts: %+v", graph)
	}
	if graph.VerdictAuthority || graph.SameOperatorClaim || graph.RealWorldIdentityClaim || graph.RugClaim || graph.WrongdoingClaim {
		t.Fatalf("trajectory graph acquired prohibited authority: %+v", graph)
	}
	if graph.EvidenceHashSHA256 == "" || graph.EvidenceHashSHA256 == "sha256:" {
		t.Fatalf("missing evidence hash: %+v", graph)
	}

	foundFunding := false
	foundCreation := false
	foundLifecycle := false
	foundVerdict := false
	foundExit := false
	previousObservedAt := ""
	for _, edge := range graph.Edges {
		if previousObservedAt != "" && edge.ObservedAt < previousObservedAt {
			t.Fatalf("edges are not time ordered: previous=%s current=%s", previousObservedAt, edge.ObservedAt)
		}
		previousObservedAt = edge.ObservedAt
		switch edge.EvidenceKind {
		case "funding":
			foundFunding = edge.SourceID == funder && edge.TargetID == creator && edge.Signature == fundingSignature && edge.Slot == 1101 && edge.EvidenceState == "verified"
		case "creation":
			foundCreation = edge.SourceID == creator && edge.TargetID == mint && edge.Signature == creationSignature && edge.Slot == 1201 && edge.EvidenceState == "verified"
		case "lifecycle":
			foundLifecycle = edge.SourceID == creator && edge.TargetID == mint && edge.Relation == "lifecycle_inactive_or_dead" && edge.EvidenceState == "verified"
		case "signed_verdict":
			foundVerdict = edge.SourceID == mint && edge.TargetID == "verdict:"+verdictFingerprint && edge.Signature == verdictSignature && edge.EvidenceState == "signed_artifact"
		case "exit_event":
			foundExit = edge.SourceID == creator && edge.TargetID == mint && edge.Relation == "liquidity_removal" && edge.Signature == exitSignature && edge.Slot == 1301 && edge.EvidenceState == "verified"
		}
	}
	if !foundFunding || !foundCreation || !foundLifecycle || !foundVerdict || !foundExit {
		t.Fatalf("missing expected trajectory edges: funding=%v creation=%v lifecycle=%v verdict=%v exit=%v edges=%+v", foundFunding, foundCreation, foundLifecycle, foundVerdict, foundExit, graph.Edges)
	}

	funderGraph, err := LoadPersistentFundingTrajectoryGraph(ctx, db, funder, network, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !funderGraph.Available || funderGraph.FundingEdgeCount != 1 || funderGraph.EdgeCount != 5 {
		t.Fatalf("funder-centric trajectory graph missing: %+v", funderGraph)
	}
}
