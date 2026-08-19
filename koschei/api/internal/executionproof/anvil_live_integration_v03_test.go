//go:build integration

package executionproof

import (
	"context"
	"os"
	"testing"
	"time"
)

const (
	liveEthereumChainID        uint64 = 1
	liveEthereumReferenceBlock uint64 = 20000000
	liveEthereumReferenceHash         = "0xd24fd73f794058a3807db926d8898c6481e902b7edb91ce0d479d6760f276183"
	liveEthereumSender                = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
)

func TestLivePinnedEthereumForkProducesVerifiedReceipt(t *testing.T) {
	forkURL := os.Getenv("KOSCHEI_LIVE_FORK_URL")
	anvilPath := os.Getenv("KOSCHEI_ANVIL_PATH")
	if forkURL == "" || anvilPath == "" {
		t.Skip("live fork proof requires KOSCHEI_LIVE_FORK_URL and KOSCHEI_ANVIL_PATH")
	}

	runnerSHA, err := fileSHA256(anvilPath)
	if err != nil {
		t.Fatalf("hash Anvil runner: %v", err)
	}

	policy := TreasuryBoundPolicy{Target: liveEthereumSender, MaxValueWei: "0x0"}
	policySHA, ok := TreasuryBoundPolicyDigest(policy)
	if !ok {
		t.Fatal("treasury policy did not canonicalize")
	}
	registry := StaticInvariantPolicyRegistry{
		TreasuryBound: map[string]TreasuryBoundPolicy{policySHA: policy},
	}

	request := VerifiedForkRequest{
		Version:            ExecutionProofForkBindingVersion,
		ChainID:            liveEthereumChainID,
		ReferenceBlock:     liveEthereumReferenceBlock,
		ReferenceBlockHash: liveEthereumReferenceHash,
		Payload: EVMPayload{
			From:     liveEthereumSender,
			To:       liveEthereumSender,
			ValueHex: "0x0",
			DataHex:  "0x",
		},
		RunnerSHA256: runnerSHA,
		Invariants: []ApprovedInvariantDefinition{{
			ID:               "live-zero-value-bound",
			Class:            InvariantTreasuryBound,
			ParametersSHA256: policySHA,
		}},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	backend := AnvilForkBackend{
		AnvilPath:      anvilPath,
		ForkURL:        forkURL,
		StartupTimeout: 30 * time.Second,
		RPCTimeout:     10 * time.Second,
		Evaluator:      PolicyBoundInvariantEvaluator{Registry: registry},
	}

	receipt, err := RunVerifiedForkExecution(ctx, request, backend)
	if err != nil {
		t.Fatalf("live pinned fork execution failed: %v", err)
	}
	if !ValidVerifiedForkReceipt(receipt) {
		t.Fatalf("live pinned fork produced invalid verified receipt: %#v", receipt)
	}
	if receipt.Simulation.ChainID != liveEthereumChainID || receipt.Simulation.ReferenceBlock != liveEthereumReferenceBlock {
		t.Fatalf("live receipt escaped pinned fork identity: chain=%d block=%d", receipt.Simulation.ChainID, receipt.Simulation.ReferenceBlock)
	}
	if !equalHex32(receipt.Simulation.ReferenceBlockHash, liveEthereumReferenceHash) {
		t.Fatalf("live receipt escaped pinned block hash: %s", receipt.Simulation.ReferenceBlockHash)
	}
	if len(receipt.Simulation.Checks) != 1 || !receipt.Simulation.Checks[0].Passed {
		t.Fatalf("live invariant did not pass: %#v", receipt.Simulation.Checks)
	}
}
