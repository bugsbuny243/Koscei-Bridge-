package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func testGoogleCredentialsJSON(t *testing.T, tokenURI string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	privateKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	raw, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     "koschei-test",
		"private_key_id": "test-key",
		"private_key":    privateKey,
		"client_email":   "publisher@koschei-test.iam.gserviceaccount.com",
		"token_uri":      tokenURI,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return string(raw)
}

func TestLoadGooglePlayCredentialsSupportsInlineBase64AndFile(t *testing.T) {
	raw := testGoogleCredentialsJSON(t, "https://oauth2.googleapis.com/token")

	t.Run("inline", func(t *testing.T) {
		t.Setenv("GOOGLE_PLAY_SERVICE_ACCOUNT_JSON", raw)
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "")
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		credentials, source, err := loadGooglePlayCredentials()
		if err != nil || source != "inline_json" || credentials.ClientEmail == "" {
			t.Fatalf("inline credentials = %#v source=%s err=%v", credentials, source, err)
		}
	})

	t.Run("base64", func(t *testing.T) {
		t.Setenv("GOOGLE_PLAY_SERVICE_ACCOUNT_JSON", "")
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "base64:"+base64.StdEncoding.EncodeToString([]byte(raw)))
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		credentials, source, err := loadGooglePlayCredentials()
		if err != nil || source != "base64_json" || credentials.ClientEmail == "" {
			t.Fatalf("base64 credentials = %#v source=%s err=%v", credentials, source, err)
		}
	})

	t.Run("file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "google-play.json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		t.Setenv("GOOGLE_PLAY_SERVICE_ACCOUNT_JSON", "")
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "")
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
		credentials, source, err := loadGooglePlayCredentials()
		if err != nil || source != "file_path" || credentials.ClientEmail == "" {
			t.Fatalf("file credentials = %#v source=%s err=%v", credentials, source, err)
		}
	})
}

func TestGooglePlayPublisherUploadsInternalDraft(t *testing.T) {
	var mu sync.Mutex
	calls := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/token":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "jwt-bearer") {
				t.Fatalf("token request missing JWT grant: %s", body)
			}
			_, _ = w.Write([]byte(`{"access_token":"token-123","token_type":"Bearer","expires_in":3600}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/edits"):
			_, _ = w.Write([]byte(`{"id":"edit-1"}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/bundles"):
			if r.Header.Get("Authorization") != "Bearer token-123" {
				t.Fatalf("bundle authorization = %q", r.Header.Get("Authorization"))
			}
			bundle, _ := io.ReadAll(r.Body)
			if string(bundle) != "fake-aab" {
				t.Fatalf("bundle body = %q", bundle)
			}
			_, _ = w.Write([]byte(`{"versionCode":42}`))
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/tracks/internal"):
			var track googlePlayTrack
			if err := json.NewDecoder(r.Body).Decode(&track); err != nil {
				t.Fatalf("track JSON error = %v", err)
			}
			if track.Track != "internal" || len(track.Releases) != 1 || track.Releases[0].Status != "draft" || track.Releases[0].VersionCodes[0] != "42" {
				t.Fatalf("unexpected track payload: %#v", track)
			}
			_, _ = w.Write([]byte(`{"track":"internal"}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, ":commit"):
			_, _ = w.Write([]byte(`{"id":"edit-1"}`))
		default:
			http.Error(w, `{"error":{"message":"unexpected request"}}`, http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Setenv("GOOGLE_PLAY_SERVICE_ACCOUNT_JSON", testGoogleCredentialsJSON(t, server.URL+"/token"))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("ANDROID_PLAY_PACKAGE_NAME", "com.koschei.game")
	t.Setenv("GOOGLE_PLAY_TRACK", "internal")
	t.Setenv("GOOGLE_PLAY_RELEASE_STATUS", "draft")
	t.Setenv("GOOGLE_PLAY_API_BASE_URL", server.URL+"/androidpublisher/v3")
	t.Setenv("GOOGLE_PLAY_UPLOAD_BASE_URL", server.URL+"/upload/androidpublisher/v3")

	publisher, source, account, err := newGooglePlayPublisher(context.Background())
	if err != nil {
		t.Fatalf("newGooglePlayPublisher() error = %v", err)
	}
	if source != "inline_json" || !strings.Contains(account, "@koschei-test.iam.gserviceaccount.com") {
		t.Fatalf("publisher metadata source=%s account=%s", source, account)
	}
	result, err := publisher.PublishAAB(context.Background(), []byte("fake-aab"), "Preview 1", "Internal test")
	if err != nil {
		t.Fatalf("PublishAAB() error = %v", err)
	}
	if result.VersionCode != 42 || result.Track != "internal" || result.Status != "draft" {
		t.Fatalf("unexpected publish result: %#v", result)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 5 {
		t.Fatalf("calls = %#v, want token + edit + bundle + track + commit", calls)
	}
}

func TestGooglePlaySafetyDefaults(t *testing.T) {
	if got := safeGooglePlayTrack("production"); got != "internal" {
		t.Fatalf("production track should require code change, got %q", got)
	}
	if got := safeGooglePlayReleaseStatus(""); got != "draft" {
		t.Fatalf("default release status = %q", got)
	}
}
