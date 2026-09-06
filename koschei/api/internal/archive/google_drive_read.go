package archive

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxDriveJSONReadBytes int64 = 16 << 20

var driveAPIBaseURL = "https://www.googleapis.com/drive/v3"

type driveFileMetadata struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	AppProperties map[string]string `json:"appProperties"`
}

// GetJSON downloads one archive object and verifies its durable koschei_sha256
// metadata before returning bytes. Hash mismatch is fail-closed.
func (d *DriveArchive) GetJSON(ctx context.Context, fileID string) (DriveObject, []byte, error) {
	if d == nil {
		return DriveObject{}, nil, errors.New("nil Google Drive archive")
	}
	fileID = strings.TrimSpace(fileID)
	if fileID == "" {
		return DriveObject{}, nil, errors.New("google drive file id is required")
	}
	token, err := d.token(ctx)
	if err != nil {
		return DriveObject{}, nil, err
	}
	metadata, err := d.getMetadata(ctx, token, fileID)
	if err != nil {
		return DriveObject{}, nil, err
	}
	expectedHash := strings.ToLower(strings.TrimSpace(metadata.AppProperties["koschei_sha256"]))
	if expectedHash == "" {
		return DriveObject{}, nil, errors.New("google drive archive object is missing koschei_sha256 metadata")
	}

	endpoint := strings.TrimRight(driveAPIBaseURL, "/") + "/files/" + url.PathEscape(fileID) + "?alt=media"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return DriveObject{}, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := d.client.Do(req)
	if err != nil {
		return DriveObject{}, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return DriveObject{}, nil, fmt.Errorf("google drive download failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxDriveJSONReadBytes+1))
	if err != nil {
		return DriveObject{}, nil, err
	}
	if int64(len(payload)) > maxDriveJSONReadBytes {
		return DriveObject{}, nil, fmt.Errorf("google drive archive object exceeds %d byte read limit", maxDriveJSONReadBytes)
	}
	actual := fmt.Sprintf("%x", sha256.Sum256(payload))
	if actual != expectedHash {
		return DriveObject{}, nil, fmt.Errorf("google drive archive checksum mismatch: expected=%s actual=%s", expectedHash, actual)
	}
	return DriveObject{ID: metadata.ID, Name: metadata.Name, Hash: actual}, payload, nil
}

// GetLatestJSONByName finds the newest object with the exact sanitized JSON name
// inside the configured archive folder and returns it only after checksum verification.
func (d *DriveArchive) GetLatestJSONByName(ctx context.Context, name string) (DriveObject, []byte, error) {
	if d == nil {
		return DriveObject{}, nil, errors.New("nil Google Drive archive")
	}
	name = safeJSONName(name)
	token, err := d.token(ctx)
	if err != nil {
		return DriveObject{}, nil, err
	}
	fileID, err := d.findLatestFileID(ctx, token, name)
	if err != nil {
		return DriveObject{}, nil, err
	}
	return d.GetJSON(ctx, fileID)
}

func (d *DriveArchive) getMetadata(ctx context.Context, token, fileID string) (driveFileMetadata, error) {
	values := url.Values{}
	values.Set("fields", "id,name,appProperties")
	endpoint := strings.TrimRight(driveAPIBaseURL, "/") + "/files/" + url.PathEscape(fileID) + "?" + values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return driveFileMetadata{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := d.client.Do(req)
	if err != nil {
		return driveFileMetadata{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return driveFileMetadata{}, fmt.Errorf("google drive metadata failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	var metadata driveFileMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return driveFileMetadata{}, err
	}
	if strings.TrimSpace(metadata.ID) == "" {
		return driveFileMetadata{}, errors.New("google drive metadata response did not contain file id")
	}
	return metadata, nil
}

func (d *DriveArchive) findLatestFileID(ctx context.Context, token, name string) (string, error) {
	query := fmt.Sprintf("name = '%s' and '%s' in parents and trashed = false", driveQueryEscape(name), driveQueryEscape(d.folderID))
	values := url.Values{}
	values.Set("q", query)
	values.Set("orderBy", "createdTime desc")
	values.Set("pageSize", "1")
	values.Set("spaces", "drive")
	values.Set("fields", "files(id,name,appProperties)")
	values.Set("supportsAllDrives", "true")
	values.Set("includeItemsFromAllDrives", "true")
	endpoint := strings.TrimRight(driveAPIBaseURL, "/") + "/files?" + values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("google drive lookup failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	var result struct {
		Files []driveFileMetadata `json:"files"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Files) == 0 || strings.TrimSpace(result.Files[0].ID) == "" {
		return "", fmt.Errorf("google drive archive object not found: %s", name)
	}
	return result.Files[0].ID, nil
}

func driveQueryEscape(value string) string {
	return strings.NewReplacer("\\", "\\\\", "'", "\\'").Replace(strings.TrimSpace(value))
}
