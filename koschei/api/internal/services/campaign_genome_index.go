package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const CampaignGenomeIndexSchemaVersion = "koschei-campaign-genome-index-v1"

type CampaignGenomeSnapshot struct {
	ID                           string                          `json:"id,omitempty"`
	SnapshotKey                  string                          `json:"snapshot_key"`
	SchemaVersion                string                          `json:"schema_version"`
	GenomeVersion                string                          `json:"genome_version"`
	Network                      string                          `json:"network"`
	ActorWallet                  string                          `json:"actor_wallet"`
	GenomeID                     string                          `json:"genome_id"`
	PatternHashSHA256            string                          `json:"pattern_hash_sha256"`
	EvidenceHashSHA256           string                          `json:"evidence_hash_sha256"`
	DescriptorCount              int                             `json:"descriptor_count"`
	VerifiedDescriptorCount      int                             `json:"verified_descriptor_count"`
	ObservedDescriptorCount      int                             `json:"observed_descriptor_count"`
	VerifiedSignatureBackedCount int                             `json:"verified_signature_backed_count"`
	WatchDescriptorCount         int                             `json:"watch_descriptor_count"`
	Descriptors                  []ActorCampaignGenomeDescriptor `json:"descriptors"`
	WatchDescriptors             []ActorCampaignGenomeDescriptor `json:"watch_descriptors"`
	Policy                       map[string]any                  `json:"policy"`
	RecordHash                   string                          `json:"record_hash"`
	ObservedAt                   time.Time                       `json:"observed_at"`
	CreatedAt                    time.Time                       `json:"created_at,omitempty"`
}

type CampaignGenomePatternMatch struct {
	ActorWallet     string    `json:"actor_wallet"`
	GenomeID        string    `json:"genome_id"`
	SnapshotKey     string    `json:"snapshot_key"`
	EvidenceHash    string    `json:"evidence_hash_sha256"`
	RecordHash      string    `json:"record_hash"`
	DescriptorCount int       `json:"descriptor_count"`
	VerifiedAnchors int       `json:"verified_signature_backed_count"`
	ObservedAt      time.Time `json:"observed_at"`
}

type CampaignGenomeMatchReport struct {
	Version                string                       `json:"version"`
	Network                string                       `json:"network"`
	ActorWallet            string                       `json:"actor_wallet"`
	GenomeID               string                       `json:"genome_id,omitempty"`
	PatternHashSHA256      string                       `json:"pattern_hash_sha256,omitempty"`
	Available              bool                         `json:"available"`
	Complete               bool                         `json:"complete"`
	Status                 string                       `json:"status"`
	MatchCount             int                          `json:"match_count"`
	OtherActorCount        int                          `json:"other_actor_count"`
	Matches                []CampaignGenomePatternMatch `json:"matches"`
	VerdictAuthority       bool                         `json:"verdict_authority"`
	SameOperatorClaim      bool                         `json:"same_operator_claim"`
	RealWorldIdentityClaim bool                         `json:"real_world_identity_claim"`
	WrongdoingClaim        bool                         `json:"wrongdoing_claim"`
	Limitations            []string                     `json:"limitations"`
}

func PersistCampaignGenomeSnapshot(ctx context.Context, db *sql.DB, genome ActorCampaignGenome) (CampaignGenomeSnapshot, bool, error) {
	snapshot, err := campaignGenomeSnapshotFromGenome(genome, time.Now().UTC())
	if err != nil {
		return CampaignGenomeSnapshot{}, false, err
	}
	if db == nil {
		return snapshot, false, fmt.Errorf("campaign genome database is unavailable")
	}
	descriptorsRaw, err := json.Marshal(snapshot.Descriptors)
	if err != nil {
		return snapshot, false, err
	}
	watchRaw, err := json.Marshal(snapshot.WatchDescriptors)
	if err != nil {
		return snapshot, false, err
	}
	policyRaw, err := json.Marshal(snapshot.Policy)
	if err != nil {
		return snapshot, false, err
	}

	var id, recordHash string
	var observedAt, createdAt time.Time
	err = db.QueryRowContext(ctx, `
		INSERT INTO security_campaign_genome_index (
			snapshot_key,schema_version,genome_version,network,actor_wallet,genome_id,
			pattern_hash_sha256,evidence_hash_sha256,descriptor_count,verified_descriptor_count,
			observed_descriptor_count,verified_signature_backed_count,watch_descriptor_count,
			descriptors,watch_descriptors,policy,record_hash,observed_at,created_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15::jsonb,$16::jsonb,$17,$18,now()
		)
		ON CONFLICT (snapshot_key) DO NOTHING
		RETURNING id::text,record_hash,observed_at,created_at`,
		snapshot.SnapshotKey, snapshot.SchemaVersion, snapshot.GenomeVersion, snapshot.Network,
		snapshot.ActorWallet, snapshot.GenomeID, snapshot.PatternHashSHA256, snapshot.EvidenceHashSHA256,
		snapshot.DescriptorCount, snapshot.VerifiedDescriptorCount, snapshot.ObservedDescriptorCount,
		snapshot.VerifiedSignatureBackedCount, snapshot.WatchDescriptorCount,
		string(descriptorsRaw), string(watchRaw), string(policyRaw), snapshot.RecordHash, snapshot.ObservedAt,
	).Scan(&id, &recordHash, &observedAt, &createdAt)
	if err == sql.ErrNoRows {
		err = db.QueryRowContext(ctx, `
			SELECT id::text,record_hash,observed_at,created_at
			FROM security_campaign_genome_index WHERE snapshot_key=$1`, snapshot.SnapshotKey).
			Scan(&id, &recordHash, &observedAt, &createdAt)
		if err != nil {
			return snapshot, false, err
		}
		snapshot.ID, snapshot.RecordHash = id, recordHash
		snapshot.ObservedAt, snapshot.CreatedAt = observedAt.UTC(), createdAt.UTC()
		return snapshot, false, nil
	}
	if err != nil {
		return snapshot, false, err
	}
	snapshot.ID, snapshot.RecordHash = id, recordHash
	snapshot.ObservedAt, snapshot.CreatedAt = observedAt.UTC(), createdAt.UTC()
	return snapshot, true, nil
}

func LoadCampaignGenomePatternMatches(ctx context.Context, db *sql.DB, genome ActorCampaignGenome, limit int) (CampaignGenomeMatchReport, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	out := CampaignGenomeMatchReport{
		Version: CampaignGenomeIndexSchemaVersion, Network: normalizeRadarNetwork(genome.Network),
		ActorWallet: strings.TrimSpace(genome.ActorWallet), GenomeID: strings.TrimSpace(genome.GenomeID),
		PatternHashSHA256: strings.TrimSpace(genome.PatternHashSHA256), Status: "no_pattern_match", Complete: true,
		Matches: []CampaignGenomePatternMatch{}, VerdictAuthority: false, SameOperatorClaim: false,
		RealWorldIdentityClaim: false, WrongdoingClaim: false, Limitations: []string{},
	}
	if !genome.Complete || genome.VerifiedSignatureBacked < 1 || out.PatternHashSHA256 == "" || out.ActorWallet == "" {
		out.Status = "genome_not_eligible"
		out.Complete = false
		out.Limitations = append(out.Limitations, "Current campaign genome is not verified-supported with a signature-backed anchor; cross-actor matching was withheld.")
		return out, nil
	}
	if db == nil {
		out.Status = "source_unavailable"
		out.Complete = false
		out.Limitations = append(out.Limitations, "Campaign genome index database is unavailable.")
		return out, nil
	}

	rows, err := db.QueryContext(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (actor_wallet)
			       actor_wallet,genome_id,snapshot_key,evidence_hash_sha256,record_hash,
			       descriptor_count,verified_signature_backed_count,observed_at,created_at
			FROM security_campaign_genome_index
			WHERE network=$1 AND pattern_hash_sha256=$2 AND actor_wallet<>$3
			ORDER BY actor_wallet,created_at DESC,id DESC
		)
		SELECT actor_wallet,genome_id,snapshot_key,evidence_hash_sha256,record_hash,
		       descriptor_count,verified_signature_backed_count,observed_at
		FROM latest
		ORDER BY observed_at DESC,actor_wallet ASC
		LIMIT $4`, out.Network, out.PatternHashSHA256, out.ActorWallet, limit)
	if err != nil {
		if isSecurityRadarMissingRelation(err) {
			out.Status = "source_unavailable"
			out.Complete = false
			out.Limitations = append(out.Limitations, "Campaign genome index schema is unavailable.")
			return out, nil
		}
		return out, err
	}
	defer rows.Close()
	actors := map[string]bool{}
	for rows.Next() {
		var item CampaignGenomePatternMatch
		if err := rows.Scan(
			&item.ActorWallet, &item.GenomeID, &item.SnapshotKey, &item.EvidenceHash,
			&item.RecordHash, &item.DescriptorCount, &item.VerifiedAnchors, &item.ObservedAt,
		); err != nil {
			return out, err
		}
		item.ObservedAt = item.ObservedAt.UTC()
		out.Matches = append(out.Matches, item)
		actors[item.ActorWallet] = true
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	out.MatchCount = len(out.Matches)
	out.OtherActorCount = len(actors)
	out.Available = out.MatchCount > 0
	if out.Available {
		out.Status = "technical_pattern_matches_observed"
	}
	out.Limitations = append(out.Limitations,
		"Pattern matching compares normalized technical behavior descriptors only; counterpart addresses and token mints are excluded from the pattern hash.",
		"Matching genomes across wallet addresses do not prove common control, common real-world identity, malicious intent or wrongdoing.",
	)
	return out, nil
}

func campaignGenomeSnapshotFromGenome(genome ActorCampaignGenome, observedAt time.Time) (CampaignGenomeSnapshot, error) {
	actor := strings.TrimSpace(genome.ActorWallet)
	network := normalizeRadarNetwork(genome.Network)
	patternHash := strings.TrimSpace(genome.PatternHashSHA256)
	evidenceHash := strings.TrimSpace(genome.EvidenceHashSHA256)
	genomeID := strings.TrimSpace(genome.GenomeID)
	if !genome.Complete || genome.Status != "verified_supported" || genome.VerifiedSignatureBacked < 1 {
		return CampaignGenomeSnapshot{}, fmt.Errorf("campaign genome is not verified-supported")
	}
	if actor == "" || genomeID == "" || !isSHA256EvidenceHash(patternHash) || !isSHA256EvidenceHash(evidenceHash) {
		return CampaignGenomeSnapshot{}, fmt.Errorf("campaign genome has incomplete identity or hashes")
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	snapshot := CampaignGenomeSnapshot{
		SchemaVersion: CampaignGenomeIndexSchemaVersion, GenomeVersion: strings.TrimSpace(genome.Version),
		Network: network, ActorWallet: actor, GenomeID: genomeID,
		PatternHashSHA256: patternHash, EvidenceHashSHA256: evidenceHash,
		DescriptorCount: genome.DescriptorCount, VerifiedDescriptorCount: genome.VerifiedDescriptorCount,
		ObservedDescriptorCount: genome.ObservedDescriptorCount, VerifiedSignatureBackedCount: genome.VerifiedSignatureBacked,
		WatchDescriptorCount: genome.WatchDescriptorCount,
		Descriptors: append([]ActorCampaignGenomeDescriptor{}, genome.Descriptors...),
		WatchDescriptors: append([]ActorCampaignGenomeDescriptor{}, genome.WatchDescriptors...),
		Policy: cloneCampaignGenomePolicy(genome.Policy), ObservedAt: observedAt.UTC(),
	}
	if snapshot.GenomeVersion == "" {
		snapshot.GenomeVersion = ActorCampaignGenomeVersion
	}
	snapshot.SnapshotKey = campaignGenomeSnapshotKey(snapshot)
	snapshot.RecordHash = campaignGenomeSnapshotRecordHash(snapshot)
	return snapshot, nil
}

func campaignGenomeSnapshotKey(snapshot CampaignGenomeSnapshot) string {
	canonical := strings.Join([]string{
		snapshot.SchemaVersion, snapshot.GenomeVersion, snapshot.Network, snapshot.ActorWallet,
		snapshot.GenomeID, snapshot.PatternHashSHA256, snapshot.EvidenceHashSHA256,
	}, "\x1f")
	digest := sha256.Sum256([]byte(canonical))
	return "KCGS1-" + hex.EncodeToString(digest[:])
}

func campaignGenomeSnapshotRecordHash(snapshot CampaignGenomeSnapshot) string {
	// observed_at/created_at are collection metadata, not snapshot identity. A
	// repeated persist of identical evidence must produce the same record hash.
	snapshot.ID, snapshot.RecordHash, snapshot.SnapshotKey = "", "", ""
	snapshot.ObservedAt, snapshot.CreatedAt = time.Time{}, time.Time{}
	payload, _ := json.Marshal(snapshot)
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func cloneCampaignGenomePolicy(value map[string]any) map[string]any {
	out := map[string]any{}
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out[key] = value[key]
	}
	return out
}

func isSHA256EvidenceHash(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}
