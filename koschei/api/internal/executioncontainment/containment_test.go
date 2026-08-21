package executioncontainment

import (
	"bytes"
	"testing"
)

const (
	digestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	digestC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	digestD = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	digestE = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

func validInputFixture() CellInput {
	return CellInput{Version: Version, ChainID: 1, BlockNumber: 123456, BlockHash: digestA, Target: "0x1111111111111111111111111111111111111111", ApprovedIntentSHA256: digestB, CandidateIntentSHA256: digestB, ApprovedPayloadSHA256: digestC, CandidatePayloadSHA256: digestC, ActionSHA256: digestA, InvariantSetSHA256: digestD, ApprovedRunnerSHA256: digestE}
}

func validObservationFixture() Observation {
	return Observation{BackendAvailable: true, ObservedChainID: 1, ObservedBlockNumber: 123456, ObservedBlockHash: digestA, ObservedRunnerSHA256: digestE, PreStateSHA256: digestA, PostStateSHA256: digestB, EffectSetSHA256: digestC, AuthorityPreserved: true, AssetBoundsPreserved: true, CodeIntegrityPreserved: true, ExecutionPathFullyObserved: true, InvariantsPass: true}
}

func TestEvaluateReleasesOnlyVerifiedSafeCell(t *testing.T) {
	receipt, err := Evaluate(validInputFixture(), validObservationFixture())
	if err != nil { t.Fatal(err) }
	if receipt.Decision != DecisionRelease { t.Fatalf("decision = %s, want RELEASE; reasons=%v", receipt.Decision, receipt.Reasons) }
	if len(receipt.Reasons) != 0 { t.Fatalf("unexpected reasons: %v", receipt.Reasons) }
	if !Verify(receipt) { t.Fatal("fresh receipt did not verify") }
}

func TestEvaluateContainsMutatedPayload(t *testing.T) {
	input := validInputFixture(); input.CandidatePayloadSHA256 = digestD
	receipt, err := Evaluate(input, validObservationFixture()); if err != nil { t.Fatal(err) }
	if receipt.Decision != DecisionContain || !containsReason(receipt.Reasons, ReasonIntentMismatch) { t.Fatalf("decision=%s reasons=%v", receipt.Decision, receipt.Reasons) }
}

func TestEvaluateRejectsMissingFullActionIdentity(t *testing.T) {
	input := validInputFixture(); input.ActionSHA256 = ""
	receipt, err := Evaluate(input, validObservationFixture()); if err != nil { t.Fatal(err) }
	if receipt.Decision != DecisionContain || !containsReason(receipt.Reasons, ReasonInvalidEvidence) { t.Fatalf("decision=%s reasons=%v", receipt.Decision, receipt.Reasons) }
}

func TestEvaluateContainsAuthorityChange(t *testing.T) {
	observation := validObservationFixture(); observation.AuthorityPreserved = false
	receipt, err := Evaluate(validInputFixture(), observation); if err != nil { t.Fatal(err) }
	if receipt.Decision != DecisionContain || !containsReason(receipt.Reasons, ReasonAuthorityChanged) { t.Fatalf("decision=%s reasons=%v", receipt.Decision, receipt.Reasons) }
}

func TestEvaluateContainsHiddenExecutionPath(t *testing.T) {
	observation := validObservationFixture(); observation.ExecutionPathFullyObserved = false
	receipt, err := Evaluate(validInputFixture(), observation); if err != nil { t.Fatal(err) }
	if receipt.Decision != DecisionContain || !containsReason(receipt.Reasons, ReasonHiddenExecutionPath) { t.Fatalf("decision=%s reasons=%v", receipt.Decision, receipt.Reasons) }
}

func TestEvaluateUnavailableFailsClosed(t *testing.T) {
	receipt, err := Evaluate(validInputFixture(), Observation{BackendAvailable: false}); if err != nil { t.Fatal(err) }
	if receipt.Decision != DecisionUnavailable || !containsReason(receipt.Reasons, ReasonBackendUnavailable) { t.Fatalf("decision=%s reasons=%v", receipt.Decision, receipt.Reasons) }
}

func TestEvaluatePinnedStateMismatchContains(t *testing.T) {
	observation := validObservationFixture(); observation.ObservedBlockHash = digestD
	receipt, err := Evaluate(validInputFixture(), observation); if err != nil { t.Fatal(err) }
	if receipt.Decision != DecisionContain || !containsReason(receipt.Reasons, ReasonPinnedStateMismatch) { t.Fatalf("decision=%s reasons=%v", receipt.Decision, receipt.Reasons) }
}

func TestEvaluateRunnerIdentityMismatchContains(t *testing.T) {
	observation := validObservationFixture(); observation.ObservedRunnerSHA256 = digestD
	receipt, err := Evaluate(validInputFixture(), observation); if err != nil { t.Fatal(err) }
	if receipt.Decision != DecisionContain || !containsReason(receipt.Reasons, ReasonRunnerIdentityMismatch) { t.Fatalf("decision=%s reasons=%v", receipt.Decision, receipt.Reasons) }
}

func TestReceiptDeterministic(t *testing.T) {
	first, err := Evaluate(validInputFixture(), validObservationFixture()); if err != nil { t.Fatal(err) }
	second, err := Evaluate(validInputFixture(), validObservationFixture()); if err != nil { t.Fatal(err) }
	firstBytes, err := CanonicalBytes(first); if err != nil { t.Fatal(err) }
	secondBytes, err := CanonicalBytes(second); if err != nil { t.Fatal(err) }
	if !bytes.Equal(firstBytes, secondBytes) { t.Fatalf("receipts differ:\n%s\n%s", firstBytes, secondBytes) }
}

func TestVerifyRejectsTamperedReceipt(t *testing.T) {
	receipt, err := Evaluate(validInputFixture(), validObservationFixture()); if err != nil { t.Fatal(err) }
	receipt.Observation.PostStateSHA256 = digestD
	if Verify(receipt) { t.Fatal("tampered receipt verified") }
}

func containsReason(reasons []ReasonCode, target ReasonCode) bool {
	for _, reason := range reasons { if reason == target { return true } }
	return false
}
