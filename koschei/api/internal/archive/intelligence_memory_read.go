package archive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const intelligenceMemoryLookupLimit = 10

// GetLatestIntelligenceMemory resolves the newest Drive-backed ARVIS memory for
// an exact kind/network/target tuple. The filename prefix is only an index hint;
// the downloaded envelope must still match the full target hash, kind and network.
func (d *DriveArchive) GetLatestIntelligenceMemory(ctx context.Context, kind, network, target string) (IntelligenceMemoryEnvelope, DriveObject, error) {
	if d == nil {
		return IntelligenceMemoryEnvelope{}, DriveObject{}, errors.New("nil Google Drive archive")
	}
	kind = normalizeMemorySegment(kind, "investigation")
	network = normalizeMemorySegment(network, "unknown-network")
	target = strings.TrimSpace(target)
	if target == "" {
		return IntelligenceMemoryEnvelope{}, DriveObject{}, errors.New("intelligence memory target is required")
	}
	fullHash := intelligenceTargetHash(network, kind, target)
	shortHash := fullHash
	if len(shortHash) > 20 {
		shortHash = shortHash[:20]
	}
	prefix := fmt.Sprintf("arvis-memory-%s-%s-%s-", kind, network, shortHash)

	token, err := d.token(ctx)
	if err != nil {
		return IntelligenceMemoryEnvelope{}, DriveObject{}, err
	}
	fileIDs, err := d.findLatestMemoryFileIDs(ctx, token, prefix)
	if err != nil {
		return IntelligenceMemoryEnvelope{}, DriveObject{}, err
	}
	for _, fileID := range fileIDs {
		object, payload, readErr := d.GetJSON(ctx, fileID)
		if readErr != nil {
			return IntelligenceMemoryEnvelope{}, DriveObject{}, readErr
		}
		var envelope IntelligenceMemoryEnvelope
		if err := json.Unmarshal(payload, &envelope); err != nil {
			return IntelligenceMemoryEnvelope{}, DriveObject{}, fmt.Errorf("decode intelligence memory envelope: %w", err)
		}
		if envelope.SchemaVersion != intelligenceMemorySchemaVersion {
			continue
		}
		if normalizeMemorySegment(envelope.Kind, "investigation") != kind || normalizeMemorySegment(envelope.Network, "unknown-network") != network {
			continue
		}
		if strings.ToLower(strings.TrimSpace(envelope.TargetHash)) != fullHash {
			continue
		}
		if envelope.Payload == nil {
			envelope.Payload = map[string]any{}
		}
		return envelope, object, nil
	}
	return IntelligenceMemoryEnvelope{}, DriveObject{}, fmt.Errorf("verified intelligence memory not found for kind=%s network=%s", kind, network)
}

func (d *DriveArchive) findLatestMemoryFileIDs(ctx context.Context, token, prefix string) ([]string, error) {
	query := fmt.Sprintf("name contains '%s' and '%s' in parents and trashed = false", driveQueryEscape(prefix), driveQueryEscape(d.folderID))
	values := url.Values{}
	values.Set("q", query)
	values.Set("orderBy", "createdTime desc")
	values.Set("pageSize", fmt.Sprintf("%d", intelligenceMemoryLookupLimit))
	values.Set("spaces", "drive")
	values.Set("fields", "files(id,name,appProperties)")
	values.Set("supportsAllDrives", "true")
	values.Set("includeItemsFromAllDrives", "true")
	endpoint := strings.TrimRight(driveAPIBaseURL, "/") + "/files?" + values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("google drive intelligence memory lookup failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	var result struct {
		Files []driveFileMetadata `json:"files"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(result.Files))
	for _, file := range result.Files {
		if id := strings.TrimSpace(file.ID); id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("google drive intelligence memory not found for prefix %s", prefix)
	}
	return ids, nil
}
