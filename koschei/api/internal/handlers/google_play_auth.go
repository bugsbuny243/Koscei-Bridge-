package handlers

import (
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
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const googleAndroidPublisherScope = "https://www.googleapis.com/auth/androidpublisher"

type googlePlayCredentials struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	TokenURI     string `json:"token_uri"`
}

type googleOAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func loadGooglePlayCredentials() (googlePlayCredentials, string, error) {
	value := firstNonEmpty(
		strings.TrimSpace(os.Getenv("GOOGLE_PLAY_SERVICE_ACCOUNT_JSON")),
		strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON")),
		strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")),
	)
	if value == "" {
		return googlePlayCredentials{}, "missing", errors.New("google play service account credentials are missing")
	}

	raw, source, err := googleCredentialBytes(value)
	if err != nil {
		return googlePlayCredentials{}, source, err
	}
	var credentials googlePlayCredentials
	if err := json.Unmarshal(raw, &credentials); err != nil {
		return googlePlayCredentials{}, source, errors.New("google play service account JSON is invalid")
	}
	credentials.PrivateKey = strings.ReplaceAll(credentials.PrivateKey, `\n`, "\n")
	credentials.TokenURI = firstNonEmpty(strings.TrimSpace(credentials.TokenURI), "https://oauth2.googleapis.com/token")
	if credentials.ClientEmail == "" || credentials.PrivateKey == "" {
		return googlePlayCredentials{}, source, errors.New("google play service account is missing client_email or private_key")
	}
	return credentials, source, nil
}

func googleCredentialBytes(value string) ([]byte, string, error) {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "{") {
		return []byte(trimmed), "inline_json", nil
	}
	if strings.HasPrefix(strings.ToLower(trimmed), "base64:") {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(trimmed[len("base64:"):]))
		if err != nil {
			return nil, "base64_json", errors.New("google play credential base64 is invalid")
		}
		return raw, "base64_json", nil
	}
	if raw, err := os.ReadFile(trimmed); err == nil {
		return raw, "file_path", nil
	}
	if raw, err := base64.StdEncoding.DecodeString(trimmed); err == nil && strings.HasPrefix(strings.TrimSpace(string(raw)), "{") {
		return raw, "base64_json", nil
	}
	return nil, "unknown", errors.New("GOOGLE_APPLICATION_CREDENTIALS must contain JSON, base64 JSON, or a readable file path")
}

func googlePlayAccessToken(ctx context.Context, credentials googlePlayCredentials) (string, error) {
	privateKey, err := parseGoogleRSAPrivateKey(credentials.PrivateKey)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	if credentials.PrivateKeyID != "" {
		header["kid"] = credentials.PrivateKeyID
	}
	claims := map[string]any{
		"iss":   credentials.ClientEmail,
		"scope": googleAndroidPublisherScope,
		"aud":   credentials.TokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(55 * time.Minute).Unix(),
	}
	assertion, err := signGoogleJWT(header, claims, privateKey)
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, credentials.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := googlePlayHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("google oauth token request failed: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var token googleOAuthTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return "", errors.New("google oauth token response is invalid")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || token.AccessToken == "" {
		return "", fmt.Errorf("google oauth rejected service account: %s", firstNonEmpty(token.Description, token.Error, response.Status))
	}
	return token.AccessToken, nil
}

func parseGoogleRSAPrivateKey(value string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, errors.New("google play private key PEM is invalid")
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if key, ok := parsed.(*rsa.PrivateKey); ok {
			return key, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("google play private key is not RSA")
}

func signGoogleJWT(header, claims map[string]any, key *rsa.PrivateKey) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoder := base64.RawURLEncoding
	unsigned := encoder.EncodeToString(headerJSON) + "." + encoder.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + encoder.EncodeToString(signature), nil
}

func maskGoogleEmail(value string) string {
	parts := strings.Split(strings.TrimSpace(value), "@")
	if len(parts) != 2 || parts[0] == "" {
		return "configured"
	}
	prefix := parts[0]
	if len(prefix) > 3 {
		prefix = prefix[:3]
	}
	return prefix + "***@" + parts[1]
}
