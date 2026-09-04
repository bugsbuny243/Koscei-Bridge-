package archive

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"sync"
	"time"
)

const driveScope = "https://www.googleapis.com/auth/drive.file"

type DriveArchive struct {
	folderID string
	client   *http.Client
	creds    serviceAccountCredentials

	mu          sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

type serviceAccountCredentials struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

type DriveObject struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Hash string `json:"sha256"`
}

func NewGoogleDriveFromEnv() (*DriveArchive, error) {
	folderID := strings.TrimSpace(os.Getenv("GOOGLE_DRIVE_ARCHIVE_FOLDER_ID"))
	raw := strings.TrimSpace(os.Getenv("GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON"))
	if folderID == "" || raw == "" {
		return nil, errors.New("google drive archive is not configured")
	}
	var creds serviceAccountCredentials
	if err := json.Unmarshal([]byte(raw), &creds); err != nil {
		return nil, errors.New("invalid Google Drive service account configuration")
	}
	if strings.TrimSpace(creds.ClientEmail) == "" || strings.TrimSpace(creds.PrivateKey) == "" {
		return nil, errors.New("incomplete Google Drive service account configuration")
	}
	if strings.TrimSpace(creds.TokenURI) == "" {
		creds.TokenURI = "https://oauth2.googleapis.com/token"
	}
	return &DriveArchive{folderID: folderID, client: &http.Client{Timeout: 30 * time.Second}, creds: creds}, nil
}

func (d *DriveArchive) PutJSON(ctx context.Context, name string, payload []byte) (DriveObject, error) {
	if d == nil {
		return DriveObject{}, errors.New("nil Google Drive archive")
	}
	name = safeJSONName(name)
	hashBytes := sha256.Sum256(payload)
	hash := fmt.Sprintf("%x", hashBytes[:])
	token, err := d.token(ctx)
	if err != nil {
		return DriveObject{}, err
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	metaHeader := textproto.MIMEHeader{}
	metaHeader.Set("Content-Type", "application/json; charset=UTF-8")
	metaPart, _ := mw.CreatePart(metaHeader)
	_ = json.NewEncoder(metaPart).Encode(map[string]any{
		"name":    name,
		"parents": []string{d.folderID},
		"appProperties": map[string]string{
			"koschei_sha256": hash,
			"koschei_kind":   "evidence_archive",
		},
	})
	dataHeader := textproto.MIMEHeader{}
	dataHeader.Set("Content-Type", "application/json")
	dataPart, _ := mw.CreatePart(dataHeader)
	_, _ = dataPart.Write(payload)
	_ = mw.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsAllDrives=true&fields=id,name", &body)
	if err != nil {
		return DriveObject{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := d.client.Do(req)
	if err != nil {
		return DriveObject{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return DriveObject{}, fmt.Errorf("google drive upload failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	var result struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return DriveObject{}, err
	}
	return DriveObject{ID: result.ID, Name: result.Name, Hash: hash}, nil
}

func (d *DriveArchive) token(ctx context.Context) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.accessToken != "" && time.Now().Add(60*time.Second).Before(d.tokenExpiry) {
		return d.accessToken, nil
	}
	assertion, err := d.jwtAssertion()
	if err != nil {
		return "", err
	}
	form := "grant_type=" + urlEncode("urn:ietf:params:oauth:grant-type:jwt-bearer") + "&assertion=" + urlEncode(assertion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.creds.TokenURI, strings.NewReader(form))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("google oauth token request failed: status=%d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if strings.TrimSpace(out.AccessToken) == "" {
		return "", errors.New("google oauth response did not contain an access token")
	}
	d.accessToken = out.AccessToken
	if out.ExpiresIn <= 0 {
		out.ExpiresIn = 3600
	}
	d.tokenExpiry = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return d.accessToken, nil
}

func (d *DriveArchive) jwtAssertion() (string, error) {
	now := time.Now().Unix()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss":   d.creds.ClientEmail,
		"scope": driveScope,
		"aud":   d.creds.TokenURI,
		"iat":   now,
		"exp":   now + 3600,
	})
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	block, _ := pem.Decode([]byte(d.creds.PrivateKey))
	if block == nil {
		return "", errors.New("invalid Google service-account private key")
	}
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("Google service-account key is not RSA")
		}
	} else {
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", errors.New("invalid Google service-account RSA key")
		}
		key = parsed
	}
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func safeJSONName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "koschei-evidence-" + time.Now().UTC().Format("20060102T150405Z")
	}
	name = strings.NewReplacer("/", "-", "\\", "-", "..", "-").Replace(name)
	if !strings.HasSuffix(strings.ToLower(name), ".json") {
		name += ".json"
	}
	return name
}

func urlEncode(v string) string {
	return strings.NewReplacer("%", "%25", ":", "%3A", "/", "%2F", "+", "%2B", "=", "%3D", " ", "+").Replace(v)
}
