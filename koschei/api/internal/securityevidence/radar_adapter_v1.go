package securityevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const (
	RadarProducerV1        = "arvis-radar/koschei-customer-investigation-response-v3"
	RadarRulesetV1         = "koschei-unified-radar-rules-v1.4.0"
	RadarResponseSurfaceV1 = "/api/token/scan"
)

type RadarReportInput struct {
	ReportJSON []byte
	Subject    Subject
	Window     ObservationWindow
	Findings   []Finding
	Legacy     *LegacyObservation
}

// BuildRadarEventV1 converts an existing ARVIS full-scan result into a
// SecurityEvidenceEvent without giving Radar signing or execution authority.
// The exact report bytes are hashed and bound as source evidence. Consumers
// can therefore detect any report substitution or mutation after emission.
func BuildRadarEventV1(in RadarReportInput) (Event, error) {
	if len(in.ReportJSON) == 0 {
		return Event{}, errors.New("radar report bytes are required")
	}
	var probe any
	if err := json.Unmarshal(in.ReportJSON, &probe); err != nil {
		return Event{}, errors.New("radar report must be valid json")
	}

	sum := sha256.Sum256(in.ReportJSON)
	reportDigest := hex.EncodeToString(sum[:])

	e := Event{
		SchemaVersion: SchemaVersionV1,
		Producer:      RadarProducerV1 + "@" + RadarRulesetV1,
		Subject:       in.Subject,
		Window:        in.Window,
		SourceDigests: []string{reportDigest},
		Findings:      append([]Finding(nil), in.Findings...),
		Legacy:        in.Legacy,
	}
	return e.Seal()
}
