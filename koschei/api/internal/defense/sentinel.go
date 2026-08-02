package defense

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const defaultSentinelLease = 90 * time.Second

type ProgramMonitorInput struct {
	ProgramID           string `json:"program_id"`
	Network             string `json:"network"`
	ManifestArtifactRef string `json:"manifest_artifact_ref,omitempty"`
	IntervalSeconds     int    `json:"interval_seconds,omitempty"`
}

type ProgramMonitor struct {
	MonitorRef          string     `json:"monitor_ref"`
	ProgramID           string     `json:"program_id"`
	Network             string     `json:"network"`
	ManifestArtifactRef string     `json:"manifest_artifact_ref,omitempty"`
	Active              bool       `json:"active"`
	IntervalSeconds     int        `json:"interval_seconds"`
	NextCheckAt         time.Time  `json:"next_check_at"`
	LeaseOwner          string     `json:"lease_owner,omitempty"`
	LeaseExpiresAt      *time.Time `json:"lease_expires_at,omitempty"`
	LastSnapshotRef     string     `json:"last_snapshot_ref,omitempty"`
	LastStatus          string     `json:"last_status"`
	LastError           string     `json:"last_error,omitempty"`
	LastCheckedAt       *time.Time `json:"last_checked_at,omitempty"`
	CreatedBy           string     `json:"created_by"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type ProgramDeploymentChange struct {
	ChangeTypes []string `json:"change_types"`
	Severity    string   `json:"severity"`
	Summary     string   `json:"summary"`
	Changed     bool     `json:"changed"`
}

type ProgramChangeEvent struct {
	EventRef            string    `json:"event_ref"`
	MonitorRef          string    `json:"monitor_ref"`
	ProgramID           string    `json:"program_id"`
	Network             string    `json:"network"`
	PreviousSnapshotRef string    `json:"previous_snapshot_ref"`
	CurrentSnapshotRef  string    `json:"current_snapshot_ref"`
	ChangeTypes         []string  `json:"change_types"`
	Severity            string    `json:"severity"`
	Summary             string    `json:"summary"`
	EvidenceRefs        []string  `json:"evidence_refs"`
	Limitations         []string  `json:"limitations"`
	EventHash           string    `json:"event_hash"`
	VerdictAuthority    bool      `json:"verdict_authority"`
	CreatedAt           time.Time `json:"created_at"`
}

type SentinelCheckResult struct {
	Monitor          ProgramMonitor          `json:"monitor"`
	Previous         *DeploymentSnapshot     `json:"previous_snapshot,omitempty"`
	Current          DeploymentSnapshot      `json:"current_snapshot"`
	Change           ProgramDeploymentChange `json:"change"`
	Event            *ProgramChangeEvent     `json:"event,omitempty"`
	BaselineCreated  bool                    `json:"baseline_created"`
	VerdictAuthority bool                    `json:"verdict_authority"`
}

func UpsertProgramMonitor(ctx context.Context, db *sql.DB, input ProgramMonitorInput) (ProgramMonitor, error) {
	if db == nil {
		return ProgramMonitor{}, errors.New("database unavailable")
	}
	input.ProgramID = strings.TrimSpace(input.ProgramID)
	input.Network = normalizedNetwork(input.Network)
	input.ManifestArtifactRef = strings.TrimSpace(input.ManifestArtifactRef)
	if input.ProgramID == "" {
		return ProgramMonitor{}, errors.New("program_id is required")
	}
	if input.IntervalSeconds == 0 {
		input.IntervalSeconds = 900
	}
	if input.IntervalSeconds < 60 || input.IntervalSeconds > 86400 {
		return ProgramMonitor{}, errors.New("interval_seconds must be between 60 and 86400")
	}
	if input.ManifestArtifactRef != "" {
		artifact, err := LoadArtifact(ctx, db, input.ManifestArtifactRef)
		if err != nil {
			return ProgramMonitor{}, errors.New("manifest artifact not found")
		}
		if artifact.ProgramID != input.ProgramID || normalizedNetwork(artifact.Network) != input.Network ||
			(artifact.ArtifactType != "source_manifest" && artifact.ArtifactType != "sbpf_manifest") {
			return ProgramMonitor{}, errors.New("manifest artifact does not match the monitored program")
		}
	}
	identity := map[string]any{"program_id": input.ProgramID, "network": input.Network}
	monitorRef := prefixedID("KDM1-", identity)
	_, err := db.ExecContext(ctx, `INSERT INTO defense_program_monitors
		(monitor_ref,program_id,network,manifest_artifact_ref,active,interval_seconds,next_check_at,last_status,created_by)
		VALUES($1,$2,$3,NULLIF($4,''),true,$5,now(),'pending','owner')
		ON CONFLICT(program_id,network) DO UPDATE SET
			manifest_artifact_ref=EXCLUDED.manifest_artifact_ref,
			active=true,
			interval_seconds=EXCLUDED.interval_seconds,
			next_check_at=LEAST(defense_program_monitors.next_check_at,now()),
			last_status=CASE WHEN defense_program_monitors.last_status='disabled' THEN 'pending' ELSE defense_program_monitors.last_status END,
			last_error=NULL,
			updated_at=now()`, monitorRef, input.ProgramID, input.Network, input.ManifestArtifactRef, input.IntervalSeconds)
	if err != nil {
		return ProgramMonitor{}, err
	}
	return GetProgramMonitor(ctx, db, monitorRef)
}

func DisableProgramMonitor(ctx context.Context, db *sql.DB, monitorRef string) (ProgramMonitor, error) {
	res, err := db.ExecContext(ctx, `UPDATE defense_program_monitors SET active=false,last_status='disabled',lease_owner=NULL,
		lease_expires_at=NULL,updated_at=now() WHERE monitor_ref=$1`, strings.TrimSpace(monitorRef))
	if err != nil {
		return ProgramMonitor{}, err
	}
	affected, _ := res.RowsAffected()
	if affected != 1 {
		return ProgramMonitor{}, errors.New("program monitor not found")
	}
	return GetProgramMonitor(ctx, db, monitorRef)
}

func GetProgramMonitor(ctx context.Context, db *sql.DB, monitorRef string) (ProgramMonitor, error) {
	var item ProgramMonitor
	var manifest, leaseOwner, lastSnapshot, lastError sql.NullString
	var leaseExpires, lastChecked sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT monitor_ref,program_id,network,manifest_artifact_ref,active,interval_seconds,next_check_at,
		lease_owner,lease_expires_at,last_snapshot_ref,last_status,last_error,last_checked_at,created_by,created_at,updated_at
		FROM defense_program_monitors WHERE monitor_ref=$1`, strings.TrimSpace(monitorRef)).Scan(
		&item.MonitorRef, &item.ProgramID, &item.Network, &manifest, &item.Active, &item.IntervalSeconds, &item.NextCheckAt,
		&leaseOwner, &leaseExpires, &lastSnapshot, &item.LastStatus, &lastError, &lastChecked,
		&item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return ProgramMonitor{}, err
	}
	if manifest.Valid {
		item.ManifestArtifactRef = manifest.String
	}
	if leaseOwner.Valid {
		item.LeaseOwner = leaseOwner.String
	}
	if leaseExpires.Valid {
		value := leaseExpires.Time
		item.LeaseExpiresAt = &value
	}
	if lastSnapshot.Valid {
		item.LastSnapshotRef = lastSnapshot.String
	}
	if lastError.Valid {
		item.LastError = lastError.String
	}
	if lastChecked.Valid {
		value := lastChecked.Time
		item.LastCheckedAt = &value
	}
	return item, nil
}

func ListProgramMonitors(ctx context.Context, db *sql.DB, activeOnly bool, limit int) ([]ProgramMonitor, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.QueryContext(ctx, `SELECT monitor_ref FROM defense_program_monitors WHERE (NOT $1 OR active=true)
		ORDER BY updated_at DESC LIMIT $2`, activeOnly, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := []string{}
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	out := make([]ProgramMonitor, 0, len(refs))
	for _, ref := range refs {
		item, err := GetProgramMonitor(ctx, db, ref)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func ClaimDueProgramMonitor(ctx context.Context, db *sql.DB, sentinelID string, lease time.Duration) (ProgramMonitor, bool, error) {
	if db == nil {
		return ProgramMonitor{}, false, errors.New("database unavailable")
	}
	sentinelID = strings.TrimSpace(sentinelID)
	if sentinelID == "" {
		return ProgramMonitor{}, false, errors.New("sentinel_id is required")
	}
	if lease <= 0 || lease > 10*time.Minute {
		lease = defaultSentinelLease
	}
	var ref string
	err := db.QueryRowContext(ctx, `WITH candidate AS (
		SELECT id FROM defense_program_monitors
		WHERE active=true AND next_check_at<=now() AND (lease_expires_at IS NULL OR lease_expires_at<now())
		ORDER BY next_check_at ASC
		FOR UPDATE SKIP LOCKED LIMIT 1
	), claimed AS (
		UPDATE defense_program_monitors m SET lease_owner=$1,lease_expires_at=now()+$2::interval,updated_at=now()
		FROM candidate c WHERE m.id=c.id RETURNING m.monitor_ref
	) SELECT monitor_ref FROM claimed`, sentinelID, fmt.Sprintf("%d seconds", int(lease.Seconds()))).Scan(&ref)
	if errors.Is(err, sql.ErrNoRows) {
		return ProgramMonitor{}, false, nil
	}
	if err != nil {
		return ProgramMonitor{}, false, err
	}
	item, err := GetProgramMonitor(ctx, db, ref)
	return item, err == nil, err
}

func CheckProgramMonitor(ctx context.Context, db *sql.DB, rpc DeploymentRPC, monitor ProgramMonitor) (SentinelCheckResult, error) {
	if !monitor.Active {
		return SentinelCheckResult{}, errors.New("program monitor is disabled")
	}
	var previous *DeploymentSnapshot
	if monitor.LastSnapshotRef != "" {
		loaded, err := loadDeploymentSnapshot(ctx, db, monitor.LastSnapshotRef)
		if err != nil {
			return SentinelCheckResult{}, err
		}
		previous = &loaded
	}
	current, err := ResolveAndPersistDeployment(ctx, db, rpc, DeploymentResolveInput{
		ProgramID: monitor.ProgramID, Network: monitor.Network, ManifestArtifactRef: monitor.ManifestArtifactRef,
	})
	if err != nil {
		return SentinelCheckResult{}, err
	}
	result := SentinelCheckResult{Monitor: monitor, Previous: previous, Current: current, VerdictAuthority: false}
	if previous == nil {
		result.BaselineCreated = true
		result.Change = ProgramDeploymentChange{Changed: false, Severity: "informational", Summary: "İlk program dağıtım gözlemi baseline olarak kaydedildi."}
		if err := completeProgramMonitorCheck(ctx, db, monitor, current.SnapshotRef, "baseline", ""); err != nil {
			return SentinelCheckResult{}, err
		}
		updated, _ := GetProgramMonitor(ctx, db, monitor.MonitorRef)
		result.Monitor = updated
		return result, nil
	}
	result.Change = CompareDeploymentSnapshots(*previous, current)
	status := "unchanged"
	if result.Change.Changed {
		status = "changed"
		event, err := persistProgramChangeEvent(ctx, db, monitor, *previous, current, result.Change)
		if err != nil {
			return SentinelCheckResult{}, err
		}
		result.Event = &event
	}
	if err := completeProgramMonitorCheck(ctx, db, monitor, current.SnapshotRef, status, ""); err != nil {
		return SentinelCheckResult{}, err
	}
	updated, _ := GetProgramMonitor(ctx, db, monitor.MonitorRef)
	result.Monitor = updated
	return result, nil
}

func FailProgramMonitorCheck(ctx context.Context, db *sql.DB, monitor ProgramMonitor, sentinelID string, failure error) error {
	message := "program sentinel check failed"
	if failure != nil {
		message = strings.TrimSpace(failure.Error())
	}
	if len(message) > 2000 {
		message = message[:2000]
	}
	res, err := db.ExecContext(ctx, `UPDATE defense_program_monitors SET last_status='error',last_error=$3,last_checked_at=now(),
		next_check_at=now()+make_interval(secs=>interval_seconds),lease_owner=NULL,lease_expires_at=NULL,updated_at=now()
		WHERE monitor_ref=$1 AND ($2='' OR lease_owner=$2)`, monitor.MonitorRef, strings.TrimSpace(sentinelID), message)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected != 1 {
		return errors.New("program monitor failure lease was lost")
	}
	return nil
}

func completeProgramMonitorCheck(ctx context.Context, db *sql.DB, monitor ProgramMonitor, snapshotRef, status, lastError string) error {
	res, err := db.ExecContext(ctx, `UPDATE defense_program_monitors SET last_snapshot_ref=$2,last_status=$3,last_error=NULLIF($4,''),
		last_checked_at=now(),next_check_at=now()+make_interval(secs=>interval_seconds),lease_owner=NULL,lease_expires_at=NULL,updated_at=now()
		WHERE monitor_ref=$1`, monitor.MonitorRef, snapshotRef, status, lastError)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected != 1 {
		return errors.New("program monitor not found")
	}
	return nil
}

func CompareDeploymentSnapshots(previous, current DeploymentSnapshot) ProgramDeploymentChange {
	changes := []string{}
	severityRank := 0
	add := func(change string, rank int) {
		changes = append(changes, change)
		if rank > severityRank {
			severityRank = rank
		}
	}
	if previous.LoaderID != current.LoaderID || previous.LoaderKind != current.LoaderKind {
		add("loader_changed", 4)
	}
	if previous.ProgramDataAddress != current.ProgramDataAddress {
		add("programdata_address_changed", 4)
	}
	if previous.CanonicalBinaryHash != current.CanonicalBinaryHash {
		add("bytecode_changed", 4)
	}
	if previous.UpgradeAuthority != current.UpgradeAuthority {
		switch {
		case previous.UpgradeAuthority == "" && current.UpgradeAuthority != "":
			add("upgrade_authority_opened", 3)
		case previous.UpgradeAuthority != "" && current.UpgradeAuthority == "":
			add("upgrade_authority_revoked", 1)
		default:
			add("upgrade_authority_changed", 3)
		}
	}
	previousMatched := isDeploymentSourceMatch(previous.MatchStatus)
	currentMatched := isDeploymentSourceMatch(current.MatchStatus)
	if previousMatched && !currentMatched {
		add("source_match_lost", 3)
	}
	if !previousMatched && currentMatched {
		add("source_match_restored", 1)
	}
	changes = uniqueStrings(changes)
	if len(changes) == 0 {
		return ProgramDeploymentChange{Changed: false, Severity: "informational", Summary: "Program binary, loader, ProgramData, upgrade authority ve kaynak eşleşmesi değişmedi."}
	}
	severity := map[int]string{1: "informational", 2: "medium", 3: "high", 4: "critical"}[severityRank]
	if severity == "" {
		severity = "medium"
	}
	return ProgramDeploymentChange{Changed: true, ChangeTypes: changes, Severity: severity,
		Summary: "Program dağıtım kontrol yüzeyinde doğrulanmış değişiklik gözlendi: " + strings.Join(changes, ", ") + ". Bu değişiklik teknik kapasiteyi gösterir; niyet veya kötüye kullanım iddiası oluşturmaz."}
}

func isDeploymentSourceMatch(status string) bool {
	return status == "matched_full_binary" || status == "matched_after_zero_padding_normalization"
}

func persistProgramChangeEvent(ctx context.Context, db *sql.DB, monitor ProgramMonitor, previous, current DeploymentSnapshot, change ProgramDeploymentChange) (ProgramChangeEvent, error) {
	evidence := uniqueStrings([]string{
		"deployment_snapshot:" + previous.SnapshotRef,
		"deployment_snapshot:" + current.SnapshotRef,
		"artifact:" + previous.BinaryArtifactRef,
		"artifact:" + current.BinaryArtifactRef,
	})
	limitations := []string{"Deployment changes establish a technical state transition only; they do not establish actor identity, intent or wrongdoing."}
	payload := map[string]any{"monitor_ref": monitor.MonitorRef, "previous": previous.SnapshotRef, "current": current.SnapshotRef,
		"change_types": change.ChangeTypes, "severity": change.Severity, "summary": change.Summary}
	eventHash := hashJSON(payload)
	eventRef := prefixedID("KDCE1-", payload)
	evidenceRaw, _ := json.Marshal(evidence)
	limitationsRaw, _ := json.Marshal(limitations)
	typesRaw, _ := json.Marshal(change.ChangeTypes)
	now := time.Now().UTC()
	_, err := db.ExecContext(ctx, `INSERT INTO defense_program_change_events
		(event_ref,monitor_ref,program_id,network,previous_snapshot_ref,current_snapshot_ref,change_types,severity,summary,evidence_refs,limitations,event_hash,verdict_authority,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10::jsonb,$11::jsonb,$12,false,$13) ON CONFLICT(event_ref) DO NOTHING`,
		eventRef, monitor.MonitorRef, monitor.ProgramID, monitor.Network, previous.SnapshotRef, current.SnapshotRef,
		string(typesRaw), change.Severity, change.Summary, string(evidenceRaw), string(limitationsRaw), eventHash, now)
	if err != nil {
		return ProgramChangeEvent{}, err
	}
	return ProgramChangeEvent{EventRef: eventRef, MonitorRef: monitor.MonitorRef, ProgramID: monitor.ProgramID, Network: monitor.Network,
		PreviousSnapshotRef: previous.SnapshotRef, CurrentSnapshotRef: current.SnapshotRef, ChangeTypes: change.ChangeTypes,
		Severity: change.Severity, Summary: change.Summary, EvidenceRefs: evidence, Limitations: limitations,
		EventHash: eventHash, VerdictAuthority: false, CreatedAt: now}, nil
}

func loadDeploymentSnapshot(ctx context.Context, db *sql.DB, ref string) (DeploymentSnapshot, error) {
	var item DeploymentSnapshot
	var evidenceRaw, limitationsRaw []byte
	err := db.QueryRowContext(ctx, `SELECT snapshot_ref,program_id,network,loader_id,loader_kind,COALESCE(programdata_address,''),account_slot,
		COALESCE(deployment_slot,0),COALESCE(upgrade_authority,''),upgrade_authority_open,executable,full_binary_hash,canonical_binary_hash,
		full_binary_size,canonical_binary_size,trailing_zero_bytes,binary_artifact_ref,COALESCE(manifest_artifact_ref,''),COALESCE(source_commit,''),
		match_status,match_evidence_status,evidence_refs,limitations,snapshot_hash,verdict_authority,created_at
		FROM defense_program_deployments WHERE snapshot_ref=$1`, strings.TrimSpace(ref)).Scan(&item.SnapshotRef, &item.ProgramID, &item.Network,
		&item.LoaderID, &item.LoaderKind, &item.ProgramDataAddress, &item.AccountSlot, &item.DeploymentSlot, &item.UpgradeAuthority,
		&item.UpgradeAuthorityOpen, &item.Executable, &item.FullBinaryHash, &item.CanonicalBinaryHash, &item.FullBinarySize,
		&item.CanonicalBinarySize, &item.TrailingZeroBytes, &item.BinaryArtifactRef, &item.ManifestArtifactRef, &item.SourceCommit,
		&item.MatchStatus, &item.MatchEvidenceStatus, &evidenceRaw, &limitationsRaw, &item.SnapshotHash, &item.VerdictAuthority, &item.CreatedAt)
	if err != nil {
		return DeploymentSnapshot{}, err
	}
	_ = json.Unmarshal(evidenceRaw, &item.EvidenceRefs)
	_ = json.Unmarshal(limitationsRaw, &item.Limitations)
	return item, nil
}

func ListProgramChangeEvents(ctx context.Context, db *sql.DB, programID string, limit int) ([]ProgramChangeEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.QueryContext(ctx, `SELECT event_ref,monitor_ref,program_id,network,previous_snapshot_ref,current_snapshot_ref,
		change_types,severity,summary,evidence_refs,limitations,event_hash,verdict_authority,created_at
		FROM defense_program_change_events WHERE ($1='' OR program_id=$1) ORDER BY created_at DESC LIMIT $2`, strings.TrimSpace(programID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProgramChangeEvent{}
	for rows.Next() {
		var item ProgramChangeEvent
		var typesRaw, evidenceRaw, limitationsRaw []byte
		if err := rows.Scan(&item.EventRef, &item.MonitorRef, &item.ProgramID, &item.Network, &item.PreviousSnapshotRef,
			&item.CurrentSnapshotRef, &typesRaw, &item.Severity, &item.Summary, &evidenceRaw, &limitationsRaw,
			&item.EventHash, &item.VerdictAuthority, &item.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(typesRaw, &item.ChangeTypes)
		_ = json.Unmarshal(evidenceRaw, &item.EvidenceRefs)
		_ = json.Unmarshal(limitationsRaw, &item.Limitations)
		out = append(out, item)
	}
	return out, rows.Err()
}
