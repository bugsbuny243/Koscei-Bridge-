package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var googlePlayHTTPClient = &http.Client{Timeout: 2 * time.Minute}

type googlePlayPublisher struct {
	AccessToken string
	PackageName string
	Track       string
	Status      string
	APIBase     string
	UploadBase  string
}

type googlePlayPublishResult struct {
	EditID      string `json:"edit_id"`
	PackageName string `json:"package_name"`
	Track       string `json:"track"`
	Status      string `json:"status"`
	VersionCode int64  `json:"version_code"`
}

type googlePlayEdit struct {
	ID string `json:"id"`
}

type googlePlayBundle struct {
	VersionCode int64 `json:"versionCode"`
}

type googlePlayTrack struct {
	Track    string              `json:"track"`
	Releases []googlePlayRelease `json:"releases"`
}

type googlePlayRelease struct {
	Name         string                  `json:"name,omitempty"`
	Status       string                  `json:"status"`
	VersionCodes []string                `json:"versionCodes"`
	ReleaseNotes []googlePlayReleaseNote `json:"releaseNotes,omitempty"`
}

type googlePlayReleaseNote struct {
	Language string `json:"language"`
	Text     string `json:"text"`
}

func newGooglePlayPublisher(ctx context.Context) (*googlePlayPublisher, string, string, error) {
	credentials, source, err := loadGooglePlayCredentials()
	if err != nil {
		return nil, source, "", err
	}
	packageName := strings.TrimSpace(os.Getenv("ANDROID_PLAY_PACKAGE_NAME"))
	if packageName == "" {
		return nil, source, maskGoogleEmail(credentials.ClientEmail), errors.New("ANDROID_PLAY_PACKAGE_NAME is missing")
	}
	accessToken, err := googlePlayAccessToken(ctx, credentials)
	if err != nil {
		return nil, source, maskGoogleEmail(credentials.ClientEmail), err
	}
	return &googlePlayPublisher{
		AccessToken: accessToken,
		PackageName: packageName,
		Track:       safeGooglePlayTrack(os.Getenv("GOOGLE_PLAY_TRACK")),
		Status:      safeGooglePlayReleaseStatus(os.Getenv("GOOGLE_PLAY_RELEASE_STATUS")),
		APIBase:     firstNonEmpty(strings.TrimSpace(os.Getenv("GOOGLE_PLAY_API_BASE_URL")), "https://androidpublisher.googleapis.com/androidpublisher/v3"),
		UploadBase:  firstNonEmpty(strings.TrimSpace(os.Getenv("GOOGLE_PLAY_UPLOAD_BASE_URL")), "https://androidpublisher.googleapis.com/upload/androidpublisher/v3"),
	}, source, maskGoogleEmail(credentials.ClientEmail), nil
}

func googlePlayReadiness() map[string]any {
	credentials, source, err := loadGooglePlayCredentials()
	packageName := strings.TrimSpace(os.Getenv("ANDROID_PLAY_PACKAGE_NAME"))
	publisherReady := err == nil && packageName != ""
	missing := []string{}
	if err != nil {
		missing = append(missing, "GOOGLE_APPLICATION_CREDENTIALS")
	}
	if packageName == "" {
		missing = append(missing, "ANDROID_PLAY_PACKAGE_NAME")
	}
	return map[string]any{
		"ok":                        true,
		"credentials_configured":    err == nil,
		"credentials_source":        source,
		"service_account":           maskGoogleEmail(credentials.ClientEmail),
		"package_name":              packageName,
		"package_configured":        packageName != "",
		"track":                     safeGooglePlayTrack(os.Getenv("GOOGLE_PLAY_TRACK")),
		"release_status":            safeGooglePlayReleaseStatus(os.Getenv("GOOGLE_PLAY_RELEASE_STATUS")),
		"aab_upload_ready":          publisherReady,
		"source_generation_ready":   aiProviderConfigured(),
		"automatic_aab_build_ready": false,
		"automatic_pipeline_ready":  false,
		"missing_fields":            missing,
		"builder_note":              "Current API image creates Expo source bundles but does not contain Node, Java, Android SDK, or an EAS build token.",
	}
}

func (p *googlePlayPublisher) PublishAAB(ctx context.Context, aab []byte, releaseName, releaseNotes string) (googlePlayPublishResult, error) {
	if len(aab) == 0 {
		return googlePlayPublishResult{}, errors.New("aab file is empty")
	}
	edit, err := p.createEdit(ctx)
	if err != nil {
		return googlePlayPublishResult{}, err
	}
	bundle, err := p.uploadBundle(ctx, edit.ID, aab)
	if err != nil {
		return googlePlayPublishResult{}, err
	}
	if err := p.updateTrack(ctx, edit.ID, bundle.VersionCode, releaseName, releaseNotes); err != nil {
		return googlePlayPublishResult{}, err
	}
	if err := p.commitEdit(ctx, edit.ID); err != nil {
		return googlePlayPublishResult{}, err
	}
	return googlePlayPublishResult{
		EditID: edit.ID, PackageName: p.PackageName, Track: p.Track,
		Status: p.Status, VersionCode: bundle.VersionCode,
	}, nil
}

func (p *googlePlayPublisher) createEdit(ctx context.Context) (googlePlayEdit, error) {
	var edit googlePlayEdit
	endpoint := fmt.Sprintf("%s/applications/%s/edits", strings.TrimRight(p.APIBase, "/"), url.PathEscape(p.PackageName))
	if err := p.doJSON(ctx, http.MethodPost, endpoint, []byte(`{}`), &edit); err != nil {
		return edit, fmt.Errorf("google play edit creation failed: %w", err)
	}
	if edit.ID == "" {
		return edit, errors.New("google play returned an empty edit id")
	}
	return edit, nil
}

func (p *googlePlayPublisher) uploadBundle(ctx context.Context, editID string, aab []byte) (googlePlayBundle, error) {
	var bundle googlePlayBundle
	endpoint := fmt.Sprintf("%s/applications/%s/edits/%s/bundles?uploadType=media&ackBundleInstallationWarning=true", strings.TrimRight(p.UploadBase, "/"), url.PathEscape(p.PackageName), url.PathEscape(editID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(aab))
	if err != nil {
		return bundle, err
	}
	req.Header.Set("Authorization", "Bearer "+p.AccessToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	response, err := googlePlayHTTPClient.Do(req)
	if err != nil {
		return bundle, fmt.Errorf("google play bundle upload failed: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return bundle, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return bundle, googlePlayAPIError(response.StatusCode, body)
	}
	if err := json.Unmarshal(body, &bundle); err != nil {
		return bundle, errors.New("google play bundle response is invalid")
	}
	if bundle.VersionCode <= 0 {
		return bundle, errors.New("google play returned an invalid version code")
	}
	return bundle, nil
}

func (p *googlePlayPublisher) updateTrack(ctx context.Context, editID string, versionCode int64, releaseName, releaseNotes string) error {
	releaseName = strings.TrimSpace(releaseName)
	if releaseName == "" {
		releaseName = "Koschei Owner Game " + time.Now().UTC().Format("2006-01-02 15:04")
	}
	release := googlePlayRelease{
		Name:         releaseName,
		Status:       p.Status,
		VersionCodes: []string{strconv.FormatInt(versionCode, 10)},
	}
	if releaseNotes = strings.TrimSpace(releaseNotes); releaseNotes != "" {
		if len(releaseNotes) > 500 {
			releaseNotes = releaseNotes[:500]
		}
		release.ReleaseNotes = []googlePlayReleaseNote{{Language: "tr-TR", Text: releaseNotes}}
	}
	payload, _ := json.Marshal(googlePlayTrack{Track: p.Track, Releases: []googlePlayRelease{release}})
	endpoint := fmt.Sprintf("%s/applications/%s/edits/%s/tracks/%s", strings.TrimRight(p.APIBase, "/"), url.PathEscape(p.PackageName), url.PathEscape(editID), url.PathEscape(p.Track))
	if err := p.doJSON(ctx, http.MethodPut, endpoint, payload, nil); err != nil {
		return fmt.Errorf("google play track update failed: %w", err)
	}
	return nil
}

func (p *googlePlayPublisher) commitEdit(ctx context.Context, editID string) error {
	endpoint := fmt.Sprintf("%s/applications/%s/edits/%s:commit", strings.TrimRight(p.APIBase, "/"), url.PathEscape(p.PackageName), url.PathEscape(editID))
	if err := p.doJSON(ctx, http.MethodPost, endpoint, []byte(`{}`), nil); err != nil {
		return fmt.Errorf("google play edit commit failed: %w", err)
	}
	return nil
}

func (p *googlePlayPublisher) doJSON(ctx context.Context, method, endpoint string, payload []byte, output any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	response, err := googlePlayHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return googlePlayAPIError(response.StatusCode, body)
	}
	if output != nil && len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, output); err != nil {
			return errors.New("google play response is invalid")
		}
	}
	return nil
}

func googlePlayAPIError(status int, body []byte) error {
	var payload struct {
		Error struct {
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &payload)
	message := firstNonEmpty(strings.TrimSpace(payload.Error.Message), strings.TrimSpace(payload.Error.Status), http.StatusText(status))
	return fmt.Errorf("google play API %d: %s", status, message)
}

func safeGooglePlayTrack(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "internal", "alpha", "beta":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "internal"
	}
}

func safeGooglePlayReleaseStatus(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "completed") {
		return "completed"
	}
	return "draft"
}
