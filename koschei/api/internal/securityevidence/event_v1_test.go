package securityevidence

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func sampleEvent() Event {
	score := 42
	return Event{
		SchemaVersion: SchemaVersionV1,
		Producer:      "arvis-radar",
		Subject: Subject{
			Chain: "Solana",
			Type:  "Wallet",
			ID:    "ExampleSubject111",
		},
		Window: ObservationWindow{FromUnixMS: 1000, ToUnixMS: 2000},
		SourceDigests: []string{
			"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		Findings: []Finding{
			{
				ID:             "holder-concentration",
				Kind:           "holder_concentration",
				State:          StateVerified,
				Severity:       "high",
				EvidenceSHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			},
			{
				ID:       "creator-link",
				Kind:     "creator_relationship",
				State:    StateUnavailable,
				Severity: "unknown",
			},
		},
		Legacy: &LegacyObservation{Grade: "f", Score: &score},
	}
}

func TestEventCanonicalIdentityIgnoresInputOrdering(t *testing.T) {
	a := sampleEvent()
	b := sampleEvent()
	b.SourceDigests[0], b.SourceDigests[1] = b.SourceDigests[1], b.SourceDigests[0]
	b.Findings[0], b.Findings[1] = b.Findings[1], b.Findings[0]

	sealedA, err := a.Seal()
	if err != nil {
		t.Fatal(err)
	}
	sealedB, err := b.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if sealedA.EventSHA256 != sealedB.EventSHA256 {
		t.Fatalf("canonical event identity changed with ordering: %s != %s", sealedA.EventSHA256, sealedB.EventSHA256)
	}
}

func TestEventVerifyRejectsTamper(t *testing.T) {
	sealed, err := sampleEvent().Seal()
	if err != nil {
		t.Fatal(err)
	}
	sealed.Findings[0].Severity = "LOW"
	if err := sealed.Verify(); err == nil {
		t.Fatal("tampered event unexpectedly verified")
	}
}

func TestVerifiedFindingRequiresEvidenceDigest(t *testing.T) {
	e := sampleEvent()
	e.Findings[0].EvidenceSHA256 = ""
	if _, err := e.Seal(); err == nil {
		t.Fatal("verified finding without evidence digest unexpectedly sealed")
	}
}

func TestDuplicateFindingIDRejected(t *testing.T) {
	e := sampleEvent()
	e.Findings = append(e.Findings, e.Findings[0])
	if _, err := e.Seal(); err == nil {
		t.Fatal("duplicate finding id unexpectedly accepted")
	}
}

func TestLegacyGradeIsBoundAsObservationOnly(t *testing.T) {
	sealed, err := sampleEvent().Seal()
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Legacy == nil || sealed.Legacy.Grade != "F" {
		t.Fatalf("legacy presentation metadata was not normalized: %#v", sealed.Legacy)
	}
	original := sealed.EventSHA256
	sealed.Legacy.Grade = "A"
	if err := sealed.Verify(); err == nil {
		t.Fatal("legacy observation tamper must invalidate event identity")
	}
	if sealed.EventSHA256 != original {
		t.Fatal("test mutated event identity field")
	}
}

func TestEventEd25519AuthenticationRejectsCallerReseal(t *testing.T) {
	privateKey := eventTestPrivateKey(0x41)
	publicKey := base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	signed, err := sampleEvent().SignEd25519(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.VerifyEd25519("arvis-radar", publicKey); err != nil {
		t.Fatalf("authenticated event did not verify: %v", err)
	}

	signed.Findings[0].Severity = "LOW"
	resealed, err := signed.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := resealed.Verify(); err != nil {
		t.Fatalf("caller-resealed digest fixture is invalid: %v", err)
	}
	if err := resealed.VerifyEd25519("arvis-radar", publicKey); err == nil {
		t.Fatal("caller-resealed event unexpectedly passed producer authentication")
	}
}

func TestEventEd25519AuthenticationPinsProducerAndTrustKey(t *testing.T) {
	privateKey := eventTestPrivateKey(0x42)
	signed, err := sampleEvent().SignEd25519(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	if err := signed.VerifyEd25519("another-producer", publicKey); err == nil {
		t.Fatal("authenticated event was relabeled to another producer")
	}
	wrongKey := eventTestPrivateKey(0x43).Public().(ed25519.PublicKey)
	if err := signed.VerifyEd25519("arvis-radar", base64.RawURLEncoding.EncodeToString(wrongKey)); err == nil {
		t.Fatal("authenticated event verified against an unrelated trust key")
	}
}

func TestEventEd25519AuthenticationRejectsMalformedPrivateKey(t *testing.T) {
	malformed := append(ed25519.PrivateKey(nil), eventTestPrivateKey(0x44)...)
	malformed[len(malformed)-1] ^= 0xff
	if _, err := sampleEvent().SignEd25519(malformed); err == nil {
		t.Fatal("non-canonical Ed25519 private key was accepted")
	}
}

func eventTestPrivateKey(fill byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = fill
	}
	return ed25519.NewKeyFromSeed(seed)
}
