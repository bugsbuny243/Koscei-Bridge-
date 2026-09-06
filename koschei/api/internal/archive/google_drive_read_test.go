package archive

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDriveGetLatestJSONByNameVerifiesChecksum(t *testing.T) {
	payload := []byte(`{"schema_version":"koschei-wallet-intelligence-v1","ok":true}`)
	hash := fmt.Sprintf("%x", sha256.Sum256(payload))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/files" && r.URL.Query().Get("q") != "":
			if !strings.Contains(r.URL.Query().Get("q"), "wallet-abc.json") {
				t.Fatalf("lookup query=%q", r.URL.Query().Get("q"))
			}
			_, _ = fmt.Fprint(w, `{"files":[{"id":"file-1","name":"wallet-abc.json"}]}`)
		case r.URL.Path == "/files/file-1" && r.URL.Query().Get("alt") == "media":
			_, _ = w.Write(payload)
		case r.URL.Path == "/files/file-1":
			_, _ = fmt.Fprintf(w, `{"id":"file-1","name":"wallet-abc.json","appProperties":{"koschei_sha256":"%s"}}`, hash)
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
	object, got, err := drive.GetLatestJSONByName(t.Context(), "wallet-abc")
	if err != nil {
		t.Fatal(err)
	}
	if object.ID != "file-1" || object.Hash != hash {
		t.Fatalf("object=%+v", object)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload=%q", got)
	}
}

func TestDriveGetJSONFailsClosedOnChecksumMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("alt") == "media" {
			_, _ = fmt.Fprint(w, `{"tampered":true}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"id":"file-2","name":"case.json","appProperties":{"koschei_sha256":"deadbeef"}}`)
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
	if _, _, err := drive.GetJSON(t.Context(), "file-2"); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
}

func TestDriveQueryEscape(t *testing.T) {
	got := driveQueryEscape(`a'b\\c`)
	if got != `a\'b\\\\c` {
		t.Fatalf("escaped=%q", got)
	}
}
