package nodeshield

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// BPFObjectManifest binds a compiled BPF object path to an expected immutable digest.
type BPFObjectManifest struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// VerifiedBPFObject contains the exact bytes that passed digest verification.
// Privileged backends must load Bytes directly rather than reopening Path.
type VerifiedBPFObject struct {
	Name   string
	SHA256 string
	Bytes  []byte
}

func ReadVerifiedBPFObject(m BPFObjectManifest) (VerifiedBPFObject, error) {
	name := strings.TrimSpace(m.Name)
	if name == "" {
		return VerifiedBPFObject{}, fmt.Errorf("BPF object name is required")
	}
	if strings.TrimSpace(m.Path) == "" {
		return VerifiedBPFObject{}, fmt.Errorf("BPF object path is required")
	}
	expected := strings.ToLower(strings.TrimSpace(m.SHA256))
	if len(expected) != 64 {
		return VerifiedBPFObject{}, fmt.Errorf("BPF object %s has invalid sha256 length", name)
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return VerifiedBPFObject{}, fmt.Errorf("BPF object %s has invalid sha256: %w", name, err)
	}

	data, err := os.ReadFile(m.Path)
	if err != nil {
		return VerifiedBPFObject{}, fmt.Errorf("read BPF object %s: %w", name, err)
	}
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return VerifiedBPFObject{}, fmt.Errorf("BPF object %s digest mismatch: got %s", name, actual)
	}
	return VerifiedBPFObject{Name: name, SHA256: expected, Bytes: data}, nil
}

func ReadVerifiedBPFObjects(manifests []BPFObjectManifest) ([]VerifiedBPFObject, error) {
	if len(manifests) == 0 {
		return nil, fmt.Errorf("at least one BPF object manifest is required")
	}
	out := make([]VerifiedBPFObject, 0, len(manifests))
	seen := make(map[string]struct{}, len(manifests))
	for _, manifest := range manifests {
		obj, err := ReadVerifiedBPFObject(manifest)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[obj.Name]; ok {
			return nil, fmt.Errorf("duplicate BPF object name %q", obj.Name)
		}
		seen[obj.Name] = struct{}{}
		out = append(out, obj)
	}
	return out, nil
}

func VerifyBPFObjectManifest(m BPFObjectManifest) error {
	_, err := ReadVerifiedBPFObject(m)
	return err
}

func VerifyBPFObjects(manifests []BPFObjectManifest) error {
	_, err := ReadVerifiedBPFObjects(manifests)
	return err
}
