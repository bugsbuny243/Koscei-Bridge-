package defense

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

var customerArtifactTypes = map[string]bool{
	"source_bundle":   true,
	"source_manifest": true,
	"sbpf_manifest":   true,
	"anchor_idl":      true,
}

type CustomerLabSummary struct {
	RunRef          string    `json:"run_ref"`
	ArtifactRef     string    `json:"artifact_ref"`
	DetectorVersion string    `json:"detector_version"`
	Decision        string    `json:"decision"`
	RecommendedAction string  `json:"recommended_action"`
	FindingCount    int       `json:"finding_count"`
	CriticalCount   int       `json:"critical_count"`
	HighCount       int       `json:"high_count"`
	MediumCount     int       `json:"medium_count"`
	LowCount        int       `json:"low_count"`
	ReportHash      string    `json:"report_hash"`
	CreatedAt       time.Time `json:"created_at"`
}

type CustomerLabResult struct {
	Summary          CustomerLabSummary `json:"summary"`
	Report           LabReport          `json:"report"`
	VerdictAuthority bool               `json:"verdict_authority"`
	StaticOnly       bool               `json:"static_only"`
}

func StoreCustomerArtifact(ctx context.Context, db *sql.DB, input ArtifactInput, subject string) (Artifact, error) {
	if db == nil {
		return Artifact{}, errors.New("database unavailable")
	}
	subject = strings.TrimSpace(subject)
	input.ArtifactType = strings.ToLower(strings.TrimSpace(input.ArtifactType))
	if subject == "" {
		return Artifact{}, errors.New("authenticated subject is required")
	}
	if !customerArtifactTypes[input.ArtifactType] {
		return Artifact{}, errors.New("customer artifact type is not supported")
	}
	// A customer may provide evidence but may not self-assert verified trust.
	input.CreatedBy = subject
	input.Verified = false
	input.TrustLevel = "unverified"
	item, err := StoreArtifact(ctx, db, input)
	if err != nil {
		return Artifact{}, err
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO defense_artifact_subscriptions
		(artifact_ref,auth_subject,created_at) VALUES($1,$2,now())
		ON CONFLICT(artifact_ref,auth_subject) DO NOTHING`, item.ArtifactRef, subject); err != nil {
		return Artifact{}, err
	}
	// Load the canonical stored row because the content-addressed artifact may
	// already have existed under another creator.
	return LoadArtifact(ctx, db, item.ArtifactRef)
}

func ListCustomerArtifacts(ctx context.Context, db *sql.DB, subject, programID, network string, limit int) ([]ArtifactSummary, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	subject = strings.TrimSpace(subject)
	programID = strings.TrimSpace(programID)
	network = normalizedNetwork(network)
	if subject == "" {
		return nil, errors.New("authenticated subject is required")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := db.QueryContext(ctx, `SELECT a.artifact_ref,a.program_id,a.artifact_type,a.content_hash,a.trust_level,a.verified,a.created_at
		FROM defense_artifact_subscriptions s
		JOIN defense_program_artifacts a ON a.artifact_ref=s.artifact_ref
		WHERE s.auth_subject=$1 AND ($2='' OR a.program_id=$2) AND a.network=$3
		ORDER BY s.created_at DESC,a.artifact_ref LIMIT $4`, subject, programID, network, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ArtifactSummary{}
	for rows.Next() {
		var item ArtifactSummary
		if err := rows.Scan(&item.ArtifactRef, &item.ProgramID, &item.ArtifactType, &item.ContentHash, &item.TrustLevel, &item.Verified, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func LoadCustomerArtifact(ctx context.Context, db *sql.DB, ref, subject string) (Artifact, error) {
	if db == nil {
		return Artifact{}, errors.New("database unavailable")
	}
	ref = strings.TrimSpace(ref)
	subject = strings.TrimSpace(subject)
	var allowed bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM defense_artifact_subscriptions WHERE artifact_ref=$1 AND auth_subject=$2)`, ref, subject).Scan(&allowed); err != nil {
		return Artifact{}, err
	}
	if !allowed {
		return Artifact{}, sql.ErrNoRows
	}
	return LoadArtifact(ctx, db, ref)
}

func AnalyzeCustomerArtifact(ctx context.Context, db *sql.DB, ref, subject string) (CustomerLabResult, error) {
	artifact, err := LoadCustomerArtifact(ctx, db, ref, subject)
	if err != nil {
		return CustomerLabResult{}, err
	}
	report, err := AnalyzeArtifact(artifact)
	if err != nil {
		return CustomerLabResult{}, err
	}
	if err := PersistLabReport(ctx, db, report); err != nil {
		return CustomerLabResult{}, err
	}
	summary := summarizeCustomerLab(report, artifact.ArtifactRef)
	summary.RunRef = prefixedID("KDLR1-", map[string]any{
		"artifact_ref": artifact.ArtifactRef,
		"subject":      subject,
		"report_hash":  report.ReportHash,
	})
	summary.CreatedAt = time.Now().UTC()
	_, err = db.ExecContext(ctx, `INSERT INTO defense_lab_runs
		(run_ref,artifact_ref,auth_subject,detector_version,decision,finding_count,critical_count,high_count,medium_count,low_count,report_hash,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT(run_ref) DO NOTHING`, summary.RunRef, artifact.ArtifactRef, subject, summary.DetectorVersion,
		summary.Decision, summary.FindingCount, summary.CriticalCount, summary.HighCount, summary.MediumCount,
		summary.LowCount, summary.ReportHash, summary.CreatedAt)
	if err != nil {
		return CustomerLabResult{}, err
	}
	return CustomerLabResult{Summary: summary, Report: report, VerdictAuthority: false, StaticOnly: true}, nil
}

func ListCustomerLabRuns(ctx context.Context, db *sql.DB, subject string, limit int) ([]CustomerLabSummary, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, errors.New("authenticated subject is required")
	}
	if limit <= 0 || limit > 100 {
		limit = 30
	}
	rows, err := db.QueryContext(ctx, `SELECT run_ref,artifact_ref,detector_version,decision,finding_count,
		critical_count,high_count,medium_count,low_count,report_hash,created_at
		FROM defense_lab_runs WHERE auth_subject=$1 ORDER BY created_at DESC LIMIT $2`, subject, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CustomerLabSummary{}
	for rows.Next() {
		var item CustomerLabSummary
		if err := rows.Scan(&item.RunRef, &item.ArtifactRef, &item.DetectorVersion, &item.Decision, &item.FindingCount,
			&item.CriticalCount, &item.HighCount, &item.MediumCount, &item.LowCount, &item.ReportHash, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.RecommendedAction = customerLabAction(item.Decision)
		out = append(out, item)
	}
	return out, rows.Err()
}

func summarizeCustomerLab(report LabReport, artifactRef string) CustomerLabSummary {
	out := CustomerLabSummary{ArtifactRef: artifactRef, DetectorVersion: report.DetectorVersion, ReportHash: report.ReportHash}
	for _, finding := range report.Findings {
		out.FindingCount++
		switch strings.ToLower(strings.TrimSpace(finding.Severity)) {
		case "critical":
			out.CriticalCount++
		case "high":
			out.HighCount++
		case "medium":
			out.MediumCount++
		default:
			out.LowCount++
		}
	}
	switch {
	case out.CriticalCount > 0 || out.HighCount > 0:
		out.Decision = "block"
	case out.MediumCount > 0:
		out.Decision = "warn"
	case out.LowCount > 0:
		out.Decision = "review"
	default:
		out.Decision = "no_static_trigger"
	}
	out.RecommendedAction = customerLabAction(out.Decision)
	return out
}

func customerLabAction(decision string) string {
	switch decision {
	case "block":
		return "Yüksek önem taşıyan statik bulgu çözülmeden programı dağıtma veya programla değer taşıyan işlem kurma."
	case "warn":
		return "Orta önem taşıyan bulguları hesap yetkileri ve çağrı yollarıyla birlikte manuel olarak doğrula."
	case "review":
		return "Düşük önem taşıyan inceleme yüzeylerini dağıtımdan önce kod review sürecine ekle."
	default:
		return "Statik kural tetiklenmedi; bunu güvenlik garantisi sayma. Runtime ve zincir üstü testlerle devam et."
	}
}
