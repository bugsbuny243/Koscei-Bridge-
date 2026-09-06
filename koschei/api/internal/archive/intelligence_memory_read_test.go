package archive

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGetLatestIntelligenceMemoryVerifiesTargetEnvelope(t *testing.T) {
	kind := "wallet_investigation"
	network := "solana-mainnet"
	target := "Wallet111"
	fullHash := intelligenceTargetHash(network, kind, target)
	envelope := IntelligenceMemoryEnvelope{
		SchemaVersion: intelligenceMemorySchemaVersion,
		Kind:          kind,
		Network:       network,
		TargetHash:    fullHash,
		CapturedAt:    time.Unix(1_700_000_000, 0).UTC(),
		Payload:       map[string]any{"status": "ready"},
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	payloadHash := fmt.Sprintf("%x", sha256.Sum256(payload))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/files" && r.URL.Query().Get("q") != "":
			query := r.URL.Query().Get("q")
			if !strings.Contains(query, fullHash[:20]) || !strings.Contains(query, "folder-1") {
				t.Fatalf("lookup query=%q", query)
			}
			_, _ = fmt.Fprint(w, `{"files":[{"id":"memory-1"}]}`)
		case r.URL.Path == "/files/memory-1" && r.URL.Query().Get("alt") == "media":
			_, _ = w.Write(payload)
		case r.URL.Path == "/files/memory-1":
			_, _ = fmt.Fprintf(w, `{"id":"memory-1","name":"memory.json","appProperties":{"koschei_sha256":"%s"}}`, payloadHash)
		default:
			t.Fatalf("unexpected request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
	}))
	defer server.Close()

	previous := driveAPIBaseURL
	driveAPIBaseURL = server.URL
	defer func() { driveAPIBaseURL = previous }()
	drive := &DriveArchive{
		folderID:    "folder-1",
		client:      server.Client(),
		accessToken: "test-token",
		tokenExpiry: time.Now().Add(time.Hour),
	}
	gotEnvelope, object, err := drive.GetLatestIntelligenceMemory(t.Context(), kind, network, target)
	if err != nil {
		t.Fatal(err)
	}
	if object.ID != "memory-1" || object.Hash != payloadHash {
		t.Fatalf("object=%+v", object)
	}
	if gotEnvelope.TargetHash != fullHash || gotEnvelope.Kind != kind || gotEnvelope.Network != network {
		t.Fatalf("envelope=%+v", gotEnvelope)
	}
	if gotEnvelope.Payload["status"] != "ready" {
		t.Fatalf("payload=%+v", gotEnvelope.Payload)
	}
}

func TestGetLatestIntelligenceMemoryRejectsShortHashCollision(t *testing.T) {
	kind := "wallet_investigation"
	network := "solana-mainnet"
	target := "Wallet111"
	fullHash := intelligenceTargetHash(network, kind, target)
	wrongHash := fullHash[:20] + strings.Repeat("0", len(fullHash)-20)
	envelope := IntelligenceMemoryEnvelope{
		SchemaVersion: intelligenceMemorySchemaVersion,
		Kind:          kind,
		Network:       network,
		TargetHash:    wrongHash,
		CapturedAt:    time.Now().UTC(),
		Payload:       map[string]any{"status": "wrong-target"},
	}
	payload, _ := json.Marshal(envelope)
	payloadHash := fmt.Sprintf("%x", sha256.Sum256(payload))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/files":
			_, _ = fmt.Fprint(w, `{"files":[{"id":"collision"}]}`)
		case r.URL.Path == "/files/collision" && r.URL.Query().Get("alt") == "media":
			_, _ = w.Write(payload)
		case r.URL.Path == "/files/collision":
			_, _ = fmt.Fprintf(w, `{"id":"collision","name":"collision.json","appProperties":{"koschei_sha256":"%s"}}`, payloadHash)
		default:
			t.Fatalf("unexpected request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
	}))
	defer server.Close()

	previous := driveAPIBaseURL
	driveAPIBaseURL = server.URL
	defer func() { driveAPIBaseURL = previous }()
	drive := &DriveArchive{
		folderID:    "folder-1",
		client:      server.Client(),
		accessToken: "test-token",
		tokenExpiry: time.Now().Add(time.Hour),
	}
	if _, _, err := drive.GetLatestIntelligenceMemory(t.Context(), kind, network, target); err == nil || !strings.Contains(err.Error(), "verified intelligence memory not found") {
		t.Fatalf("expected full-hash rejection, got %v", err)
	}
}
