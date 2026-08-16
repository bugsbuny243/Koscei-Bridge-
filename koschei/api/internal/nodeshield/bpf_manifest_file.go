package nodeshield

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const BPFManifestSchemaV1 = "koschei.nodeshield.bpf.objects.v1"

type BPFObjectSet struct {
	Schema     string              `json:"schema"`
	TargetArch string              `json:"target_arch"`
	Objects    []BPFObjectManifest `json:"objects"`
}

func LoadBPFObjectSet(path string) (BPFObjectSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return BPFObjectSet{}, fmt.Errorf("read BPF manifest: %w", err)
	}
	var set BPFObjectSet
	if err := json.Unmarshal(data, &set); err != nil {
		return BPFObjectSet{}, fmt.Errorf("decode BPF manifest: %w", err)
	}
	if set.Schema != BPFManifestSchemaV1 {
		return BPFObjectSet{}, fmt.Errorf("unsupported BPF manifest schema %q", set.Schema)
	}
	if strings.TrimSpace(set.TargetArch) == "" {
		return BPFObjectSet{}, fmt.Errorf("BPF manifest target_arch is required")
	}
	if err := VerifyBPFObjects(set.Objects); err != nil {
		return BPFObjectSet{}, fmt.Errorf("verify BPF manifest objects: %w", err)
	}
	return set, nil
}
