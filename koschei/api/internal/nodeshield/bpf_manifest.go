package nodeshield

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// BPFObjectManifest binds a compiled BPF object to an expected immutable digest.
// A loader must verify this manifest before attempting to load or attach code.
type BPFObjectManifest struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func VerifyBPFObjectManifest(m BPFObjectManifest) error {
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("BPF object name is required")
	}
	if strings.TrimSpace(m.Path) == "" {
		return fmt.Errorf("BPF object path is required")
	}
	expected := strings.ToLower(strings.TrimSpace(m.SHA256))
	if len(expected) != 64 {
		return fmt.Errorf("BPF object %s has invalid sha256 length", m.Name)
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return fmt.Errorf("BPF object %s has invalid sha256: %w", m.Name, err)
	}

	data, err := os.ReadFile(m.Path)
	if err != nil {
		return fmt.Errorf("read BPF object %s: %w", m.Name, err)
	}
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return fmt.Errorf("BPF object %s digest mismatch: got %s", m.Name, actual)
	}
	return nil
}

func VerifyBPFObjects(manifests []BPFObjectManifest) error {
	if len(manifests) == 0 {
		return fmt.Errorf("at least one BPF object manifest is required")
	}
	for _, manifest := range manifests {
		if err := VerifyBPFObjectManifest(manifest); err != nil {
			return err
		}
	}
	return nil
}
