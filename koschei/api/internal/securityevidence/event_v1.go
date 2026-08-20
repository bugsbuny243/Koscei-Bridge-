package securityevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const SchemaVersionV1 = "koschei.security-evidence/v1"

type EvidenceState string

const (
	StateObserved      EvidenceState = "OBSERVED"
	StateVerified      EvidenceState = "VERIFIED"
	StateUnavailable   EvidenceState = "UNAVAILABLE"
	StateNotApplicable EvidenceState = "NOT_APPLICABLE"
)

type Subject struct {
	Chain string `json:"chain"`
	Type  string `json:"type"`
	ID    string `json:"id"`
}

type ObservationWindow struct {
	FromUnixMS int64 `json:"from_unix_ms"`
	ToUnixMS   int64 `json:"to_unix_ms"`
}

type Finding struct {
	ID             string        `json:"id"`
	Kind           string        `json:"kind"`
	State          EvidenceState `json:"state"`
	Severity       string        `json:"severity,omitempty"`
	EvidenceSHA256 string        `json:"evidence_sha256,omitempty"`
	Summary        string        `json:"summary,omitempty"`
}

// LegacyObservation preserves old ARVIS presentation data for compatibility.
// It is evidence metadata only and MUST NOT be used as signing or execution authority.
type LegacyObservation struct {
	Grade string `json:"grade,omitempty"`
	Score *int   `json:"score,omitempty"`
}

type Event struct {
	SchemaVersion string             `json:"schema_version"`
	Producer      string             `json:"producer"`
	Subject       Subject            `json:"subject"`
	Window        ObservationWindow  `json:"window"`
	SourceDigests []string           `json:"source_digests_sha256,omitempty"`
	Findings      []Finding          `json:"findings"`
	Legacy        *LegacyObservation `json:"legacy_observation,omitempty"`
	EventSHA256   string             `json:"event_sha256"`
}

func (e Event) Canonical() (Event, error) {
	out := e
	out.SchemaVersion = strings.TrimSpace(out.SchemaVersion)
	out.Producer = strings.TrimSpace(out.Producer)
	out.Subject.Chain = strings.ToLower(strings.TrimSpace(out.Subject.Chain))
	out.Subject.Type = strings.ToLower(strings.TrimSpace(out.Subject.Type))
	out.Subject.ID = strings.TrimSpace(out.Subject.ID)
	out.EventSHA256 = ""

	if out.SchemaVersion == "" {
		out.SchemaVersion = SchemaVersionV1
	}
	if out.SchemaVersion != SchemaVersionV1 {
		return Event{}, fmt.Errorf("unsupported schema version %q", out.SchemaVersion)
	}
	if out.Producer == "" || out.Subject.Chain == "" || out.Subject.Type == "" || out.Subject.ID == "" {
		return Event{}, errors.New("producer and complete subject identity are required")
	}
	if out.Window.FromUnixMS < 0 || out.Window.ToUnixMS < 0 || out.Window.ToUnixMS < out.Window.FromUnixMS {
		return Event{}, errors.New("invalid observation window")
	}

	seenSource := make(map[string]struct{}, len(out.SourceDigests))
	canonSources := make([]string, 0, len(out.SourceDigests))
	for _, d := range out.SourceDigests {
		d = strings.ToLower(strings.TrimSpace(d))
		if !validSHA256(d) {
			return Event{}, fmt.Errorf("invalid source digest %q", d)
		}
		if _, ok := seenSource[d]; ok {
			continue
		}
		seenSource[d] = struct{}{}
		canonSources = append(canonSources, d)
	}
	sort.Strings(canonSources)
	out.SourceDigests = canonSources

	seenFinding := make(map[string]struct{}, len(out.Findings))
	canonFindings := make([]Finding, 0, len(out.Findings))
	for _, f := range out.Findings {
		f.ID = strings.TrimSpace(f.ID)
		f.Kind = strings.ToLower(strings.TrimSpace(f.Kind))
		f.Severity = strings.ToUpper(strings.TrimSpace(f.Severity))
		f.EvidenceSHA256 = strings.ToLower(strings.TrimSpace(f.EvidenceSHA256))
		f.Summary = strings.TrimSpace(f.Summary)
		if f.ID == "" || f.Kind == "" {
			return Event{}, errors.New("finding id and kind are required")
		}
		if _, ok := seenFinding[f.ID]; ok {
			return Event{}, fmt.Errorf("duplicate finding id %q", f.ID)
		}
		seenFinding[f.ID] = struct{}{}
		switch f.State {
		case StateObserved, StateVerified, StateUnavailable, StateNotApplicable:
		default:
			return Event{}, fmt.Errorf("invalid evidence state %q", f.State)
		}
		if f.EvidenceSHA256 != "" && !validSHA256(f.EvidenceSHA256) {
			return Event{}, fmt.Errorf("invalid finding evidence digest for %q", f.ID)
		}
		if f.State == StateVerified && f.EvidenceSHA256 == "" {
			return Event{}, fmt.Errorf("verified finding %q requires evidence digest", f.ID)
		}
		canonFindings = append(canonFindings, f)
	}
	sort.Slice(canonFindings, func(i, j int) bool {
		if canonFindings[i].ID != canonFindings[j].ID {
			return canonFindings[i].ID < canonFindings[j].ID
		}
		return canonFindings[i].Kind < canonFindings[j].Kind
	})
	out.Findings = canonFindings

	if out.Legacy != nil {
		legacy := *out.Legacy
		legacy.Grade = strings.ToUpper(strings.TrimSpace(legacy.Grade))
		out.Legacy = &legacy
	}

	return out, nil
}

func (e Event) Digest() (string, error) {
	canonical, err := e.Canonical()
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func (e Event) Seal() (Event, error) {
	canonical, err := e.Canonical()
	if err != nil {
		return Event{}, err
	}
	digest, err := canonical.Digest()
	if err != nil {
		return Event{}, err
	}
	canonical.EventSHA256 = digest
	return canonical, nil
}

func (e Event) Verify() error {
	expected := strings.ToLower(strings.TrimSpace(e.EventSHA256))
	if !validSHA256(expected) {
		return errors.New("event_sha256 is required and must be sha256")
	}
	actual, err := e.Digest()
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("security evidence event digest mismatch")
	}
	return nil
}

func validSHA256(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}
