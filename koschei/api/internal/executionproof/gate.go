package executionproof

import "strings"

const ReasonProofHashMismatch ReasonCode = "EP-006-PROOF-HASH-MISMATCH"

// AuthorizeForSigning never trusts the serialized evaluation carried by a Proof.
// It recomputes the envelope decision and hash from evidence, then fails closed
// if the presented envelope hash does not match the recomputed envelope.
func AuthorizeForSigning(presented Proof) Evaluation {
	recomputed, err := Evaluate(presented.Envelope)
	if err != nil {
		return Evaluation{Decision: DecisionBlock, Reasons: []ReasonCode{ReasonInvalidEvidence}}
	}

	if !strings.EqualFold(recomputed.EnvelopeSHA256, presented.EnvelopeSHA256) {
		reasons := append([]ReasonCode{}, recomputed.Evaluation.Reasons...)
		reasons = append(reasons, ReasonProofHashMismatch)
		return Evaluation{Decision: DecisionBlock, Reasons: reasons}
	}

	return recomputed.Evaluation
}
