package defense

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxSourceArchiveBytes     = 8 * 1024 * 1024
	maxSourceArchiveExpanded  = 20 * 1024 * 1024
	maxSourceFileBytes        = 256 * 1024
	maxSourceBundleBytes      = 700 * 1024
	maxSourceBundleJSONBytes  = 850 * 1024
	maxSourceArchiveFileCount = 1200
	maxSourceBundleFileCount  = 350
)

var githubCommitPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
var githubNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

type SourceImportHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type SourceImportInput struct {
	ProgramID     string `json:"program_id"`
	Network       string `json:"network"`
	RepositoryURL string `json:"repository_url"`
	CommitSHA     string `json:"commit_sha"`
}

type SourceImportRecord struct {
	ImportRef         string    `json:"import_ref"`
	ProgramID         string    `json:"program_id"`
	Network           string    `json:"network"`
	RepositoryURL     string    `json:"repository_url"`
	RepositoryOwner   string    `json:"repository_owner"`
	RepositoryName    string    `json:"repository_name"`
	CommitSHA         string    `json:"commit_sha"`
	ArchiveHash       string    `json:"archive_hash"`
	SourceArtifactRef string    `json:"source_artifact_ref"`
	FileCount         int       `json:"file_count"`
	SourceBytes       int       `json:"source_bytes"`
	SkippedFiles      int       `json:"skipped_files"`
	Status            string    `json:"status"`
	EvidenceRefs      []string  `json:"evidence_refs"`
	Limitations       []string  `json:"limitations"`
	ImportHash        string    `json:"import_hash"`
	VerdictAuthority  bool      `json:"verdict_authority"`
	CreatedAt         time.Time `json:"created_at"`
}

type fetchedSourceArchive struct {
	RepositoryURL   string
	RepositoryOwner string
	RepositoryName  string
	CommitSHA       string
	ArchiveHash     string
	Bundle          map[string]string
	BundleJSON      []byte
	FileCount       int
	SourceBytes     int
	SkippedFiles    int
	Limitations     []string
}

type sourceCandidate struct {
	Path     string
	Content  string
	Size     int
	Priority int
}

func NewSourceImportHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 35 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 2 {
				return errors.New("too many source archive redirects")
			}
			host := strings.ToLower(req.URL.Hostname())
			if host != "codeload.github.com" {
				return fmt.Errorf("source archive redirect host is not allowed: %s", host)
			}
			return nil
		},
	}
}

func ImportSourceRepository(ctx context.Context, db *sql.DB, client SourceImportHTTPClient, input SourceImportInput) (SourceImportRecord, error) {
	if db == nil {
		return SourceImportRecord{}, errors.New("database unavailable")
	}
	fetched, err := FetchSourceRepository(ctx, client, input)
	if err != nil {
		return SourceImportRecord{}, err
	}
	artifact, err := StoreArtifact(ctx, db, ArtifactInput{
		ProgramID:       input.ProgramID,
		Network:         input.Network,
		ArtifactType:    "source_bundle",
		SourceURI:       fetched.RepositoryURL,
		SourceCommit:    fetched.CommitSHA,
		ContentEncoding: "json",
		Content:         string(fetched.BundleJSON),
		Metadata: map[string]any{
			"import_source":    "public_github_commit_archive",
			"repository_owner": fetched.RepositoryOwner,
			"repository_name":  fetched.RepositoryName,
			"archive_sha256":   fetched.ArchiveHash,
			"file_count":       fetched.FileCount,
			"source_bytes":     fetched.SourceBytes,
			"skipped_files":    fetched.SkippedFiles,
		},
		TrustLevel: "observed",
		Verified:   false,
		CreatedBy:  "owner",
	})
	if err != nil {
		return SourceImportRecord{}, err
	}

	now := time.Now().UTC()
	evidence := []string{"artifact:" + artifact.ArtifactRef, "github-archive:" + fetched.ArchiveHash, "commit:" + fetched.CommitSHA}
	limitations := append([]string{}, fetched.Limitations...)
	limitations = append(limitations,
		"The archive was fetched from a public GitHub commit URL, but repository ownership and developer identity were not independently verified.",
		"Imported source has not been compiled or matched to deployed bytecode until Phase 6 deployment verification is run with a build manifest.",
	)
	evidence = uniqueStrings(evidence)
	limitations = uniqueStrings(limitations)
	payload := map[string]any{
		"program_id":          strings.TrimSpace(input.ProgramID),
		"network":             normalizedNetwork(input.Network),
		"repository_url":      fetched.RepositoryURL,
		"commit_sha":          fetched.CommitSHA,
		"archive_hash":        fetched.ArchiveHash,
		"source_artifact_ref": artifact.ArtifactRef,
		"file_count":          fetched.FileCount,
		"source_bytes":        fetched.SourceBytes,
	}
	importHash := hashJSON(payload)
	importRef := prefixedID("KSI1-", payload)
	evidenceRaw, _ := json.Marshal(evidence)
	limitationsRaw, _ := json.Marshal(limitations)
	_, err = db.ExecContext(ctx, `INSERT INTO defense_source_imports
		(import_ref,program_id,network,repository_url,repository_owner,repository_name,commit_sha,archive_hash,source_artifact_ref,
		 file_count,source_bytes,skipped_files,status,evidence_refs,limitations,import_hash,verdict_authority,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'imported',$13::jsonb,$14::jsonb,$15,false,$16)
		ON CONFLICT(import_ref) DO NOTHING`,
		importRef, strings.TrimSpace(input.ProgramID), normalizedNetwork(input.Network), fetched.RepositoryURL, fetched.RepositoryOwner,
		fetched.RepositoryName, fetched.CommitSHA, fetched.ArchiveHash, artifact.ArtifactRef, fetched.FileCount, fetched.SourceBytes,
		fetched.SkippedFiles, string(evidenceRaw), string(limitationsRaw), importHash, now)
	if err != nil {
		return SourceImportRecord{}, err
	}
	return SourceImportRecord{
		ImportRef: importRef, ProgramID: strings.TrimSpace(input.ProgramID), Network: normalizedNetwork(input.Network),
		RepositoryURL: fetched.RepositoryURL, RepositoryOwner: fetched.RepositoryOwner, RepositoryName: fetched.RepositoryName,
		CommitSHA: fetched.CommitSHA, ArchiveHash: fetched.ArchiveHash, SourceArtifactRef: artifact.ArtifactRef,
		FileCount: fetched.FileCount, SourceBytes: fetched.SourceBytes, SkippedFiles: fetched.SkippedFiles, Status: "imported",
		EvidenceRefs: evidence, Limitations: limitations, ImportHash: importHash, VerdictAuthority: false, CreatedAt: now,
	}, nil
}

func FetchSourceRepository(ctx context.Context, client SourceImportHTTPClient, input SourceImportInput) (fetchedSourceArchive, error) {
	input.ProgramID = strings.TrimSpace(input.ProgramID)
	input.Network = normalizedNetwork(input.Network)
	if input.ProgramID == "" {
		return fetchedSourceArchive{}, errors.New("program_id is required")
	}
	owner, repo, normalizedURL, err := parsePublicGitHubRepositoryURL(input.RepositoryURL)
	if err != nil {
		return fetchedSourceArchive{}, err
	}
	commit := strings.ToLower(strings.TrimSpace(input.CommitSHA))
	if !githubCommitPattern.MatchString(commit) {
		return fetchedSourceArchive{}, errors.New("commit_sha must be an exact 40-character hexadecimal Git commit")
	}
	if client == nil {
		client = NewSourceImportHTTPClient()
	}
	archiveURL := fmt.Sprintf("https://codeload.github.com/%s/%s/zip/%s", owner, repo, commit)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL, nil)
	if err != nil {
		return fetchedSourceArchive{}, err
	}
	req.Header.Set("Accept", "application/zip")
	req.Header.Set("User-Agent", "Koschei-Defense-Source-Importer/1")
	resp, err := client.Do(req)
	if err != nil {
		return fetchedSourceArchive{}, fmt.Errorf("source archive fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fetchedSourceArchive{}, fmt.Errorf("source archive returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSourceArchiveBytes+1))
	if err != nil {
		return fetchedSourceArchive{}, err
	}
	if len(body) == 0 || len(body) > maxSourceArchiveBytes {
		return fetchedSourceArchive{}, errors.New("source archive is empty or exceeds the compressed size limit")
	}
	bundle, fileCount, sourceBytes, skipped, limitations, err := extractSourceBundleFromZip(body)
	if err != nil {
		return fetchedSourceArchive{}, err
	}
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		return fetchedSourceArchive{}, err
	}
	if len(bundleJSON) > maxSourceBundleJSONBytes {
		return fetchedSourceArchive{}, errors.New("source bundle JSON exceeds the artifact limit")
	}
	return fetchedSourceArchive{
		RepositoryURL: normalizedURL, RepositoryOwner: owner, RepositoryName: repo, CommitSHA: commit,
		ArchiveHash: hashValue(body), Bundle: bundle, BundleJSON: bundleJSON, FileCount: fileCount,
		SourceBytes: sourceBytes, SkippedFiles: skipped, Limitations: limitations,
	}, nil
}

func parsePublicGitHubRepositoryURL(raw string) (string, string, string, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" {
		return "", "", "", errors.New("repository_url must be an HTTPS GitHub repository URL")
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "github.com" && host != "www.github.com" {
		return "", "", "", errors.New("only public github.com repositories are supported")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return "", "", "", errors.New("repository_url must not contain credentials, query parameters or fragments")
	}
	parts := strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/")
	if len(parts) != 2 {
		return "", "", "", errors.New("repository_url must identify exactly owner/repository")
	}
	owner, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", "", "", errors.New("invalid repository owner")
	}
	repo, err := url.PathUnescape(parts[1])
	if err != nil {
		return "", "", "", errors.New("invalid repository name")
	}
	repo = strings.TrimSuffix(repo, ".git")
	if !githubNamePattern.MatchString(owner) || !githubNamePattern.MatchString(repo) || owner == "" || repo == "" {
		return "", "", "", errors.New("invalid GitHub owner or repository name")
	}
	return owner, repo, "https://github.com/" + owner + "/" + repo, nil
}

func extractSourceBundleFromZip(archive []byte) (map[string]string, int, int, int, []string, error) {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, 0, 0, 0, nil, errors.New("source archive is not a valid ZIP file")
	}
	if len(reader.File) == 0 || len(reader.File) > maxSourceArchiveFileCount {
		return nil, 0, 0, 0, nil, errors.New("source archive file count is outside the supported range")
	}
	candidates := []sourceCandidate{}
	expandedBytes := int64(0)
	skipped := 0
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		if file.Mode()&0o170000 == 0o120000 {
			skipped++
			continue
		}
		expandedBytes += int64(file.UncompressedSize64)
		if expandedBytes > maxSourceArchiveExpanded {
			return nil, 0, 0, 0, nil, errors.New("source archive exceeds the expanded size limit")
		}
		relative, ok := safeArchiveSourcePath(file.Name)
		if !ok || !isSecurityRelevantSourcePath(relative) || file.UncompressedSize64 == 0 || file.UncompressedSize64 > maxSourceFileBytes {
			skipped++
			continue
		}
		stream, err := file.Open()
		if err != nil {
			return nil, 0, 0, 0, nil, err
		}
		content, readErr := io.ReadAll(io.LimitReader(stream, maxSourceFileBytes+1))
		closeErr := stream.Close()
		if readErr != nil || closeErr != nil {
			return nil, 0, 0, 0, nil, errors.New("source archive file read failed")
		}
		if len(content) == 0 || len(content) > maxSourceFileBytes || !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0 {
			skipped++
			continue
		}
		candidates = append(candidates, sourceCandidate{Path: relative, Content: string(content), Size: len(content), Priority: sourcePathPriority(relative)})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority < candidates[j].Priority
		}
		return candidates[i].Path < candidates[j].Path
	})
	bundle := map[string]string{}
	total := 0
	for _, candidate := range candidates {
		if len(bundle) >= maxSourceBundleFileCount || total+candidate.Size > maxSourceBundleBytes {
			skipped++
			continue
		}
		bundle[candidate.Path] = candidate.Content
		total += candidate.Size
	}
	if len(bundle) == 0 {
		return nil, 0, 0, skipped, nil, errors.New("source archive contains no supported bounded source files")
	}
	limitations := []string{}
	if skipped > 0 {
		limitations = append(limitations, fmt.Sprintf("%d archive entries were excluded because they were generated, binary, unsafe, oversized or outside the bounded source budget.", skipped))
	}
	if len(bundle) == maxSourceBundleFileCount || total >= maxSourceBundleBytes {
		limitations = append(limitations, "Source bundle reached a configured file or byte budget; lower-priority files may be absent from static analysis.")
	}
	return bundle, len(bundle), total, skipped, limitations, nil
}

func safeArchiveSourcePath(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	clean := path.Clean("/" + name)
	clean = strings.TrimPrefix(clean, "/")
	parts := strings.Split(clean, "/")
	if len(parts) < 2 {
		return "", false
	}
	relative := path.Clean(strings.Join(parts[1:], "/"))
	if relative == "." || relative == "" || strings.HasPrefix(relative, "../") || path.IsAbs(relative) {
		return "", false
	}
	for _, part := range strings.Split(relative, "/") {
		if part == "" || part == "." || part == ".." {
			return "", false
		}
	}
	return relative, true
}

func isSecurityRelevantSourcePath(value string) bool {
	lower := strings.ToLower(value)
	for _, blocked := range []string{"/.git/", "target/", "/target/", "node_modules/", "/node_modules/", "vendor/", "/vendor/", "dist/", "/dist/", "build/", "/build/"} {
		if strings.Contains("/"+lower, blocked) {
			return false
		}
	}
	base := strings.ToLower(path.Base(lower))
	if base == "cargo.toml" || base == "cargo.lock" || base == "anchor.toml" || base == "rust-toolchain" || base == "rust-toolchain.toml" {
		return true
	}
	switch strings.ToLower(path.Ext(lower)) {
	case ".rs", ".toml", ".lock", ".json", ".yaml", ".yml", ".md", ".proto", ".ts", ".js":
		return true
	default:
		return false
	}
}

func sourcePathPriority(value string) int {
	lower := strings.ToLower(value)
	base := strings.ToLower(path.Base(lower))
	if base == "anchor.toml" || base == "cargo.toml" || base == "cargo.lock" || strings.HasPrefix(lower, "programs/") || strings.HasPrefix(lower, "src/") {
		return 0
	}
	if strings.Contains(lower, "/src/") || strings.HasPrefix(lower, "idl/") || strings.Contains(lower, "/idl/") {
		return 1
	}
	if strings.HasPrefix(lower, "tests/") || strings.Contains(lower, "/tests/") {
		return 2
	}
	return 3
}

func ListSourceImports(ctx context.Context, db *sql.DB, programID, network string, limit int) ([]SourceImportRecord, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	programID = strings.TrimSpace(programID)
	network = normalizedNetwork(network)
	rows, err := db.QueryContext(ctx, `SELECT import_ref,program_id,network,repository_url,repository_owner,repository_name,commit_sha,archive_hash,
		source_artifact_ref,file_count,source_bytes,skipped_files,status,evidence_refs,limitations,import_hash,verdict_authority,created_at
		FROM defense_source_imports WHERE ($1='' OR program_id=$1) AND network=$2 ORDER BY created_at DESC LIMIT $3`, programID, network, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SourceImportRecord{}
	for rows.Next() {
		var item SourceImportRecord
		var evidenceRaw, limitationsRaw []byte
		if err := rows.Scan(&item.ImportRef, &item.ProgramID, &item.Network, &item.RepositoryURL, &item.RepositoryOwner, &item.RepositoryName,
			&item.CommitSHA, &item.ArchiveHash, &item.SourceArtifactRef, &item.FileCount, &item.SourceBytes, &item.SkippedFiles,
			&item.Status, &evidenceRaw, &limitationsRaw, &item.ImportHash, &item.VerdictAuthority, &item.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(evidenceRaw, &item.EvidenceRefs)
		_ = json.Unmarshal(limitationsRaw, &item.Limitations)
		out = append(out, item)
	}
	return out, rows.Err()
}
