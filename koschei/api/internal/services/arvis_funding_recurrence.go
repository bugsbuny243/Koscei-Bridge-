package services

import "encoding/json"

// ArvisFundingRecurrenceFromBundle reads the typed recurrence projection stored
// in ARVIS metadata without interpreting an absent projection as evidence.
func ArvisFundingRecurrenceFromBundle(bundle SecurityRadarBundle) FundingRecurrenceAnalysis {
	out := FundingRecurrenceAnalysis{Sources: []FundingSourceRecurrence{}, Limitations: []string{}}
	if bundle.Metadata == nil {
		return out
	}
	raw, ok := bundle.Metadata["funding_recurrence"]
	if !ok || raw == nil {
		return out
	}
	if typed, ok := raw.(FundingRecurrenceAnalysis); ok {
		if typed.Sources == nil {
			typed.Sources = []FundingSourceRecurrence{}
		}
		if typed.Limitations == nil {
			typed.Limitations = []string{}
		}
		return typed
	}
	encoded, err := json.Marshal(raw)
	if err != nil || json.Unmarshal(encoded, &out) != nil {
		return FundingRecurrenceAnalysis{Status: "unknown", EvidenceStatus: "unknown", Sources: []FundingSourceRecurrence{}, Limitations: []string{"Funding recurrence metadata could not be decoded; the state is withheld."}}
	}
	if out.Sources == nil {
		out.Sources = []FundingSourceRecurrence{}
	}
	if out.Limitations == nil {
		out.Limitations = []string{}
	}
	return out
}
