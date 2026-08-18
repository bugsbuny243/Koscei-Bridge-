package executionproof

import (
    "context"
    "errors"
    "testing"

    "koschei/api/internal/matrixcontainment"
)

func containmentFixture(t *testing.T) matrixcontainment.Receipt {
    t.Helper()
    d1 := "1111111111111111111111111111111111111111111111111111111111111111"
    d2 := "2222222222222222222222222222222222222222222222222222222222222222"
    d3 := "3333333333333333333333333333333333333333333333333333333333333333"
    d4 := "4444444444444444444444444444444444444444444444444444444444444444"
    d5 := "5555555555555555555555555555555555555555555555555555555555555555"
    d6 := "6666666666666666666666666666666666666666666666666666666666666666"
    d7 := "7777777777777777777777777777777777777777777777777777777777777777"

    receipt, err := matrixcontainment.Evaluate(matrixcontainment.CellInput{
        ChainID:                1,
        BlockNumber:            23456789,
        BlockHash:              d1,
        Target:                 "0x1111111111111111111111111111111111111111",
        ApprovedIntentSHA256:   d2,
        CandidateIntentSHA256:  d2,
        ApprovedPayloadSHA256:  d3,
        CandidatePayloadSHA256: d3,
        InvariantSetSHA256:     d4,
        ApprovedRunnerSHA256:   d5,
    }, matrixcontainment.Observation{
        BackendAvailable:           true,
        ObservedChainID:            1,
        ObservedBlockNumber:        23456789,
        ObservedBlockHash:          d1,
        ObservedRunnerSHA256:       d5,
        PreStateSHA256:             d6,
        PostStateSHA256:            d7,
        EffectSetSHA256:            d4,
        AuthorityPreserved:         true,
        AssetBoundsPreserved:       true,
        CodeIntegrityPreserved:     true,
        ExecutionPathFullyObserved: true,
        InvariantsPass:             true,
    })
    if err != nil {
        t.Fatal(err)
    }
    if receipt.Decision != matrixcontainment.DecisionRelease || !matrixcontainment.Verify(receipt) {
        t.Fatalf("fixture is not verified RELEASE: decision=%s reasons=%v", receipt.Decision, receipt.Reasons)
    }
    return receipt
}

func TestVerifyContainmentAndForwardSafeTransactionForwardsOnlyVerifiedRelease(t *testing.T) {
    req, proof := nativeSafeForwardFixture(t)
    receipt := containmentFixture(t)
    forwarder := &recordingSafeForwarder{}

    got, err := VerifyContainmentAndForwardSafeTransaction(context.Background(), receipt, proof, req, forwarder)
    if err != nil {
        t.Fatal(err)
    }
    if got.Decision != DecisionAllow {
        t.Fatalf("decision=%s reasons=%v", got.Decision, got.Reasons)
    }
    if forwarder.calls != 1 {
        t.Fatalf("forward calls=%d, want 1", forwarder.calls)
    }
}

func TestVerifyContainmentAndForwardSafeTransactionNeverForwardsContain(t *testing.T) {
    req, proof := nativeSafeForwardFixture(t)
    release := containmentFixture(t)
    input := release.Input
    input.CandidatePayloadSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    contained, err := matrixcontainment.Evaluate(input, release.Observation)
    if err != nil {
        t.Fatal(err)
    }
    if contained.Decision != matrixcontainment.DecisionContain {
        t.Fatalf("containment decision=%s, want CONTAIN", contained.Decision)
    }
    forwarder := &recordingSafeForwarder{}

    got, err := VerifyContainmentAndForwardSafeTransaction(context.Background(), contained, proof, req, forwarder)
    if !errors.Is(err, ErrContainmentBlocked) {
        t.Fatalf("error=%v, want ErrContainmentBlocked", err)
    }
    if got.Decision != DecisionBlock || forwarder.calls != 0 {
        t.Fatalf("contain path escaped: decision=%s calls=%d", got.Decision, forwarder.calls)
    }
}

func TestVerifyContainmentAndForwardSafeTransactionNeverForwardsUnavailable(t *testing.T) {
    req, proof := nativeSafeForwardFixture(t)
    release := containmentFixture(t)
    unavailable, err := matrixcontainment.Evaluate(release.Input, matrixcontainment.Observation{BackendAvailable: false})
    if err != nil {
        t.Fatal(err)
    }
    if unavailable.Decision != matrixcontainment.DecisionUnavailable {
        t.Fatalf("containment decision=%s, want UNAVAILABLE", unavailable.Decision)
    }
    forwarder := &recordingSafeForwarder{}

    got, err := VerifyContainmentAndForwardSafeTransaction(context.Background(), unavailable, proof, req, forwarder)
    if !errors.Is(err, ErrContainmentBlocked) {
        t.Fatalf("error=%v, want ErrContainmentBlocked", err)
    }
    if got.Decision != DecisionBlock || forwarder.calls != 0 {
        t.Fatalf("unavailable path escaped: decision=%s calls=%d", got.Decision, forwarder.calls)
    }
}

func TestVerifyContainmentAndForwardSafeTransactionRejectsTamperedReceipt(t *testing.T) {
    req, proof := nativeSafeForwardFixture(t)
    receipt := containmentFixture(t)
    receipt.Observation.AuthorityPreserved = false
    forwarder := &recordingSafeForwarder{}

    got, err := VerifyContainmentAndForwardSafeTransaction(context.Background(), receipt, proof, req, forwarder)
    if !errors.Is(err, ErrContainmentBlocked) {
        t.Fatalf("error=%v, want ErrContainmentBlocked", err)
    }
    if got.Decision != DecisionBlock || forwarder.calls != 0 {
        t.Fatalf("tampered receipt escaped: decision=%s calls=%d", got.Decision, forwarder.calls)
    }
}
