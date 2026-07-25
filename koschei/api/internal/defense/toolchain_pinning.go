package defense

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var defenseSHA256DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// PinnedToolchainAttestation extends Phase 11 availability evidence with the
// exact executable hash and immutable worker image identity required by the
// Phase 12 execution gate.
type PinnedToolchainAttestation struct {
	AttestationRef    string    `json:"attestation_ref"`
	WorkerID          string    `json:"worker_id"`
	WorkerImageDigest string    `json:"worker_image_digest,omitempty"`
	ToolName          string    `json:"tool_name"`
	Command           string    `json:"command"`
	Available         bool      `json:"available"`
	Pinned            bool      `json:"pinned"`
	VersionOutput     string    `json:"version_output"`
	VersionHash       string    `json:"version_hash"`
	BinaryPath        string    `json:"binary_path,omitempty"`
	BinaryHash        string    `json:"binary_hash,omitempty"`
	EvidenceStatus    string    `json:"evidence_status"`
	Limitations       []string  `json:"limitations"`
	AttestationHash   string    `json:"attestation_hash"`
	VerdictAuthority  bool      `json:"verdict_authority"`
	ObservedAt        time.Time `json:"observed_at"`
}

// AttestPinnedLocalToolchain executes bounded version probes and hashes the
// exact resolved executable. Tool availability is preserved separately from
// pinning: a command may work but still be ineligible for execution when the
// worker image digest or executable hash is absent.
func AttestPinnedLocalToolchain(ctx context.Context, db *sql.DB, workerID string) ([]PinnedToolchainAttestation, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return nil, errors.New("worker_id is required")
	}
	workerImageDigest := normalizeDefenseSHA256Digest(os.Getenv("KOSCHEI_DEFENSE_WORKER_IMAGE_DIGEST"))
	commands := []struct {
		Name string
		Args []string
	}{
		{Name: "rustc", Args: []string{"rustc", "--version"}},
		{Name: "cargo", Args: []string{"cargo", "--version"}},
		{Name: "bwrap", Args: []string{"bwrap", "--version"}},
		{Name: "solana", Args: []string{"solana", "--version"}},
		{Name: "anchor", Args: []string{"anchor", "--version"}},
		{Name: "trident", Args: []string{"trident", "--version"}},
	}

	out := make([]PinnedToolchainAttestation, 0, len(commands))
	for _, spec := range commands {
		observedAt := time.Now().UTC()
		limitations := []string{}

		binaryPath, lookErr := exec.LookPath(spec.Args[0])
		binaryPath = strings.TrimSpace(binaryPath)
		binaryHash := ""
		if lookErr != nil || binaryPath == "" {
			binaryPath = ""
			limitations = append(limitations, "Tool executable could not be resolved in the worker PATH.")
		} else if digest, err := hashDefenseExecutable(binaryPath); err != nil {
			binaryPath = ""
			limitations = append(limitations, "Tool executable could not be hashed.")
		} else {
			binaryHash = digest
		}

		probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		cmd := exec.CommandContext(probeCtx, spec.Args[0], spec.Args[1:]...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=/tmp"}
		data, commandErr := cmd.CombinedOutput()
		cancel()

		version := strings.TrimSpace(string(data))
		if len(version) > 2000 {
			version = version[:2000]
		}
		available := commandErr == nil && version != ""
		evidenceStatus := "observed"
		if !available {
			evidenceStatus = "unavailable"
			limitations = append(limitations, "Tool was not available or did not return a successful version response in this worker image.")
			if version == "" && commandErr != nil {
				version = commandErr.Error()
			}
		}
		if workerImageDigest == "" {
			limitations = append(limitations, "KOSCHEI_DEFENSE_WORKER_IMAGE_DIGEST is missing or is not a sha256 digest.")
		}
		pinned := available && workerImageDigest != "" && binaryHash != ""
		versionHash := hashValue(version)
		payload := map[string]any{
			"worker_id": workerID,
			"worker_image_digest": workerImageDigest,
			"tool_name": spec.Name,
			"command": strings.Join(spec.Args, " "),
			"available": available,
			"version_hash": versionHash,
			"binary_path": binaryPath,
			"binary_hash": binaryHash,
			"observed_at": observedAt.Format(time.RFC3339Nano),
		}
		attestationHash := hashJSON(payload)
		ref := prefixedID("KTA1-", payload)
		limitationsRaw, _ := json.Marshal(uniqueStrings(limitations))
		_, persistErr := db.ExecContext(ctx, `INSERT INTO defense_toolchain_attestations
			(attestation_ref,worker_id,tool_name,command,available,version_output,version_hash,evidence_status,limitations,
			 attestation_hash,verdict_authority,observed_at,worker_image_digest,binary_path,binary_hash)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,false,$11,$12,$13,$14)`,
			ref, workerID, spec.Name, strings.Join(spec.Args, " "), available, version, versionHash, evidenceStatus,
			string(limitationsRaw), attestationHash, observedAt, workerImageDigest, binaryPath, binaryHash)
		if persistErr != nil {
			return nil, persistErr
		}
		out = append(out, PinnedToolchainAttestation{
			AttestationRef: ref, WorkerID: workerID, WorkerImageDigest: workerImageDigest, ToolName: spec.Name,
			Command: strings.Join(spec.Args, " "), Available: available, Pinned: pinned, VersionOutput: version,
			VersionHash: versionHash, BinaryPath: binaryPath, BinaryHash: binaryHash, EvidenceStatus: evidenceStatus,
			Limitations: uniqueStrings(limitations), AttestationHash: attestationHash, VerdictAuthority: false, ObservedAt: observedAt,
		})
	}
	return out, nil
}

func ListPinnedToolchainAttestations(ctx context.Context, db *sql.DB, workerID string, limit int) ([]PinnedToolchainAttestation, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.QueryContext(ctx, `SELECT attestation_ref,worker_id,COALESCE(worker_image_digest,''),tool_name,command,available,
		version_output,version_hash,COALESCE(binary_path,''),COALESCE(binary_hash,''),evidence_status,limitations,
		attestation_hash,verdict_authority,observed_at
		FROM defense_toolchain_attestations
		WHERE ($1='' OR worker_id=$1)
		ORDER BY observed_at DESC LIMIT $2`, strings.TrimSpace(workerID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []PinnedToolchainAttestation{}
	for rows.Next() {
		var item PinnedToolchainAttestation
		var limitationsRaw []byte
		if err := rows.Scan(&item.AttestationRef, &item.WorkerID, &item.WorkerImageDigest, &item.ToolName, &item.Command,
			&item.Available, &item.VersionOutput, &item.VersionHash, &item.BinaryPath, &item.BinaryHash,
			&item.EvidenceStatus, &limitationsRaw, &item.AttestationHash, &item.VerdictAuthority, &item.ObservedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(limitationsRaw, &item.Limitations)
		item.Pinned = item.Available && normalizeDefenseSHA256Digest(item.WorkerImageDigest) != "" && normalizeDefenseSHA256Digest(item.BinaryHash) != ""
		out = append(out, item)
	}
	return out, rows.Err()
}

func normalizeDefenseSHA256Digest(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if !defenseSHA256DigestPattern.MatchString(value) {
		return ""
	}
	return value
}

func hashDefenseExecutable(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}
