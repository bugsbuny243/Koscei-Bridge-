package archive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const intelligenceMemorySchemaVersion = "koschei-drive-intelligence-memory-v1"

type IntelligenceMemoryEnvelope struct {
	SchemaVersion string         `json:"schema_version"`
	Kind          string         `json:"kind"`
	Network       string         `json:"network"`
	TargetHash    string         `json:"target_hash"`
	CapturedAt    time.Time      `json:"captured_at"`
	Payload       map[string]any `json:"payload"`
}

type IntelligenceMemoryResult struct {
	Status string      `json:"status"`
	Object DriveObject `json:"object"`
}

// PutIntelligenceMemory writes a bounded, evidence-oriented ARVIS memory object
// to Google Drive. Neon/PostgreSQL is intentionally not part of this path.
func (d *DriveArchive) PutIntelligenceMemory(ctx context.Context, kind, network, target string, payload map[string]any) (IntelligenceMemoryResult, error) {
	if d == nil {
		return IntelligenceMemoryResult{Status: "drive_unavailable"}, errors.New("nil Google Drive archive")
	}
	kind = normalizeMemorySegment(kind, "investigation")
	network = normalizeMemorySegment(network, "unknown-network")
	target = strings.TrimSpace(target)
	if target == "" {
		return IntelligenceMemoryResult{Status: "invalid_target"}, errors.New("intelligence memory target is required")
	}
	clean := redactSensitiveMemory(payload)
	envelope := IntelligenceMemoryEnvelope{
		SchemaVersion: intelligenceMemorySchemaVersion,
		Kind:          kind,
		Network:       network,
		TargetHash:    intelligenceTargetHash(network, kind, target),
		CapturedAt:    time.Now().UTC(),
		Payload:       clean,
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return IntelligenceMemoryResult{Status: "encode_failed"}, fmt.Errorf("encode intelligence memory: %w", err)
	}
	name := intelligenceMemoryFilename(envelope.Kind, envelope.Network, envelope.TargetHash, envelope.CapturedAt)
	object, err := d.PutJSON(ctx, name, encoded)
	if err != nil {
		return IntelligenceMemoryResult{Status: "drive_write_failed"}, err
	}
	return IntelligenceMemoryResult{Status: "drive_archived", Object: object}, nil
}

func intelligenceTargetHash(network, kind, target string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(network) + "\x00" + strings.TrimSpace(kind) + "\x00" + strings.TrimSpace(target)))
	return hex.EncodeToString(sum[:])
}

func intelligenceMemoryFilename(kind, network, targetHash string, capturedAt time.Time) string {
	shortHash := targetHash
	if len(shortHash) > 20 {
		shortHash = shortHash[:20]
	}
	return fmt.Sprintf("arvis-memory-%s-%s-%s-%s.json",
		normalizeMemorySegment(kind, "investigation"),
		normalizeMemorySegment(network, "unknown-network"),
		shortHash,
		capturedAt.UTC().Format("20060102T150405.000000000Z"),
	)
}

func normalizeMemorySegment(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = fallback
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return fallback
	}
	return out
}

func redactSensitiveMemory(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		if sensitiveMemoryKey(key) {
			out[key] = "[REDACTED]"
			continue
		}
		out[key] = redactSensitiveValue(value)
	}
	return out
}

func redactSensitiveValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return redactSensitiveMemory(typed)
	case []any:
		out := make([]any, len(typed))
		for i := range typed {
			out[i] = redactSensitiveValue(typed[i])
		}
		return out
	default:
		return value
	}
}

func sensitiveMemoryKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	for _, token := range []string{"private_key", "seed_phrase", "mnemonic", "secret", "api_key", "access_token", "refresh_token", "authorization", "password"} {
		if strings.Contains(normalized, token) {
			return true
		}
	}
	return false
}
