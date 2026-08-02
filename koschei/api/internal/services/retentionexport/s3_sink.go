package retentionexport

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

type S3Config struct {
	Endpoint        string
	Bucket          string
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	PathStyle       bool
	HTTPClient      *http.Client
}

type S3Sink struct {
	endpoint        *url.URL
	bucket          string
	region          string
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	pathStyle       bool
	client          *http.Client
	now             func() time.Time
}

func NewS3Sink(config S3Config) (*S3Sink, error) {
	endpoint, err := url.Parse(strings.TrimSpace(config.Endpoint))
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return nil, fmt.Errorf("valid KOSCHEI_RADAR_ARCHIVE_EXPORT_S3_ENDPOINT is required")
	}
	if endpoint.Scheme != "https" && endpoint.Scheme != "http" {
		return nil, fmt.Errorf("S3 endpoint must use http or https")
	}
	if strings.TrimSpace(config.Bucket) == "" {
		return nil, fmt.Errorf("KOSCHEI_RADAR_ARCHIVE_EXPORT_S3_BUCKET is required")
	}
	if strings.TrimSpace(config.AccessKeyID) == "" || strings.TrimSpace(config.SecretAccessKey) == "" {
		return nil, fmt.Errorf("S3 access key id and secret access key are required")
	}
	region := strings.TrimSpace(config.Region)
	if region == "" {
		region = "us-east-1"
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &S3Sink{
		endpoint:        endpoint,
		bucket:          strings.TrimSpace(config.Bucket),
		region:          region,
		accessKeyID:     strings.TrimSpace(config.AccessKeyID),
		secretAccessKey: strings.TrimSpace(config.SecretAccessKey),
		sessionToken:    strings.TrimSpace(config.SessionToken),
		pathStyle:       config.PathStyle,
		client:          client,
		now:             time.Now,
	}, nil
}

func (s *S3Sink) Name() string { return "s3" }

func (s *S3Sink) Put(ctx context.Context, key string, data []byte) (string, error) {
	request, err := s.signedRequest(ctx, http.MethodPut, key, data)
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-ndjson")
	response, err := s.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 16<<10))
		return "", fmt.Errorf("S3 PUT status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return "s3://" + s.bucket + "/" + strings.TrimLeft(key, "/"), nil
}

func (s *S3Sink) Get(ctx context.Context, key string) ([]byte, error) {
	request, err := s.signedRequest(ctx, http.MethodGet, key, nil)
	if err != nil {
		return nil, err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 16<<10))
		return nil, fmt.Errorf("S3 GET status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return io.ReadAll(io.LimitReader(response.Body, 256<<20))
}

func (s *S3Sink) signedRequest(ctx context.Context, method, key string, body []byte) (*http.Request, error) {
	objectURL, err := s.objectURL(key)
	if err != nil {
		return nil, err
	}
	payloadHash := sha256Hex(body)
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, objectURL.String(), reader)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	amzDate := now.Format("20060102T150405Z")
	shortDate := now.Format("20060102")
	request.Header.Set("Host", objectURL.Host)
	request.Header.Set("X-Amz-Date", amzDate)
	request.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if s.sessionToken != "" {
		request.Header.Set("X-Amz-Security-Token", s.sessionToken)
	}

	canonicalHeaders, signedHeaders := canonicalS3Headers(request)
	canonicalRequest := strings.Join([]string{
		method,
		objectURL.EscapedPath(),
		objectURL.Query().Encode(),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")
	credentialScope := shortDate + "/" + s.region + "/s3/aws4_request"
	canonicalHash := sha256Hex([]byte(canonicalRequest))
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + credentialScope + "\n" + canonicalHash
	signingKey := awsSigningKey(s.secretAccessKey, shortDate, s.region, "s3")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.accessKeyID+"/"+credentialScope+", SignedHeaders="+signedHeaders+", Signature="+signature)
	return request, nil
}

func (s *S3Sink) objectURL(key string) (*url.URL, error) {
	if s == nil || s.endpoint == nil {
		return nil, fmt.Errorf("S3 sink is not configured")
	}
	cleanKey := path.Clean("/" + strings.TrimSpace(key))
	if cleanKey == "/" || strings.Contains(cleanKey, "..") {
		return nil, fmt.Errorf("invalid S3 object key %q", key)
	}
	objectURL := *s.endpoint
	basePath := strings.TrimSuffix(objectURL.Path, "/")
	if s.pathStyle {
		objectURL.Path = basePath + "/" + s.bucket + cleanKey
	} else {
		objectURL.Host = s.bucket + "." + objectURL.Host
		objectURL.Path = basePath + cleanKey
	}
	objectURL.RawPath = ""
	objectURL.RawQuery = ""
	objectURL.Fragment = ""
	return &objectURL, nil
}

func canonicalS3Headers(request *http.Request) (string, string) {
	headers := map[string]string{
		"host":                 strings.TrimSpace(request.URL.Host),
		"x-amz-content-sha256": strings.TrimSpace(request.Header.Get("X-Amz-Content-Sha256")),
		"x-amz-date":           strings.TrimSpace(request.Header.Get("X-Amz-Date")),
	}
	if token := strings.TrimSpace(request.Header.Get("X-Amz-Security-Token")); token != "" {
		headers["x-amz-security-token"] = token
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonical strings.Builder
	for _, name := range names {
		canonical.WriteString(name)
		canonical.WriteByte(':')
		canonical.WriteString(strings.Join(strings.Fields(headers[name]), " "))
		canonical.WriteByte('\n')
	}
	return canonical.String(), strings.Join(names, ";")
}

func awsSigningKey(secret, date, region, service string) []byte {
	dateKey := hmacSHA256([]byte("AWS4"+secret), date)
	regionKey := hmacSHA256(dateKey, region)
	serviceKey := hmacSHA256(regionKey, service)
	return hmacSHA256(serviceKey, "aws4_request")
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}
