package web3

// EvidenceCourtRequiredWitnesses returns the configured bounded quorum size.
// It exposes policy state without enabling collection or bypassing feature gates.
func EvidenceCourtRequiredWitnesses() int {
	return evidenceCourtRequiredWitnesses()
}
