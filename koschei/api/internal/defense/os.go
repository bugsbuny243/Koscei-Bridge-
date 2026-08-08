package defense

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/runtimecfg"
)

const (
	DetectorVersion  = "koschei-solana-static-v1.0.0"
	maxArtifactBytes = 900 * 1024
	maxSandboxOutput = 256 * 1024
)

var safeArtifactTypes = map[string]bool{
	"source_bundle": true, "source_manifest": true, "anchor_idl": true,
	"sbpf_bytecode": true, "sbpf_manifest": true, "knowledge_document": true,
	"synthetic_source_bundle": true,
}

var safeArtifactEncodings = map[string]bool{"utf8": true, "json": true, "base64": true, "manifest": true}

// Artifact is an immutable, hash-addressed input to the program-security lab.
type Artifact struct {
	ArtifactRef      string         `json:"artifact_ref"`
	ProgramID        string         `json:"program_id"`
	Network          string         `json:"network"`
	ArtifactType     string         `json:"artifact_type"`
	SourceURI        string         `json:"source_uri,omitempty"`
	SourceCommit     string         `json:"source_commit,omitempty"`
	Framework        string         `json:"framework,omitempty"`
	FrameworkVersion string         `json:"framework_version,omitempty"`
	RuntimeVersion   string         `json:"runtime_version,omitempty"`
	ContentHash      string         `json:"content_hash"`
	ContentEncoding  string         `json:"content_encoding"`
	Content          []byte         `json:"-"`
	Metadata         map[string]any `json:"metadata"`
	TrustLevel       string         `json:"trust_level"`
	Verified         bool           `json:"verified"`
	CreatedBy        string         `json:"created_by"`
	CreatedAt        time.Time      `json:"created_at"`
}

type ArtifactInput struct {
	ProgramID        string         `json:"program_id"`
	Network          string         `json:"network"`
	ArtifactType     string         `json:"artifact_type"`
	SourceURI        string         `json:"source_uri"`
	SourceCommit     string         `json:"source_commit"`
	Framework        string         `json:"framework"`
	FrameworkVersion string         `json:"framework_version"`
	RuntimeVersion   string         `json:"runtime_version"`
	ContentEncoding  string         `json:"content_encoding"`
	Content          string         `json:"content"`
	Metadata         map[string]any `json:"metadata"`
	TrustLevel       string         `json:"trust_level"`
	Verified         bool           `json:"verified"`
	CreatedBy        string         `json:"created_by"`
}

type ArtifactSummary struct {
	ArtifactRef  string    `json:"artifact_ref"`
	ProgramID    string    `json:"program_id"`
	ArtifactType string    `json:"artifact_type"`
	ContentHash  string    `json:"content_hash"`
	TrustLevel   string    `json:"trust_level"`
	Verified     bool      `json:"verified"`
	CreatedAt    time.Time `json:"created_at"`
}

type KnowledgeInput struct {
	Title            string         `json:"title"`
	Body             string         `json:"body"`
	SourceURI        string         `json:"source_uri"`
	SourceCommit     string         `json:"source_commit"`
	Framework        string         `json:"framework"`
	FrameworkVersion string         `json:"framework_version"`
	RuntimeVersion   string         `json:"runtime_version"`
	TrustLevel       string         `json:"trust_level"`
	Tags             []string       `json:"tags"`
	EmbeddingModel   string         `json:"embedding_model"`
	Embedding        []float64      `json:"embedding"`
	Metadata         map[string]any `json:"metadata"`
	CreatedBy        string         `json:"created_by"`
}

type KnowledgeDocument struct {
	DocumentRef      string         `json:"document_ref"`
	Title            string         `json:"title"`
	Body             string         `json:"body"`
	SourceURI        string         `json:"source_uri,omitempty"`
	SourceCommit     string         `json:"source_commit,omitempty"`
	SourceHash       string         `json:"source_hash"`
	Framework        string         `json:"framework,omitempty"`
	FrameworkVersion string         `json:"framework_version,omitempty"`
	RuntimeVersion   string         `json:"runtime_version,omitempty"`
	TrustLevel       string         `json:"trust_level"`
	Tags             []string       `json:"tags"`
	EmbeddingModel   string         `json:"embedding_model,omitempty"`
	Similarity       float64        `json:"similarity,omitempty"`
	Metadata         map[string]any `json:"metadata"`
	CreatedAt        time.Time      `json:"created_at"`
}

func StoreArtifact(ctx context.Context, db *sql.DB, input ArtifactInput) (Artifact, error) {
	if db == nil {
		return Artifact{}, errors.New("database unavailable")
	}
	input.ProgramID = strings.TrimSpace(input.ProgramID)
	input.Network = normalizedNetwork(input.Network)
	input.ArtifactType = strings.ToLower(strings.TrimSpace(input.ArtifactType))
	input.ContentEncoding = strings.ToLower(strings.TrimSpace(input.ContentEncoding))
	if input.ContentEncoding == "" {
		input.ContentEncoding = "utf8"
	}
	if input.ProgramID == "" || !safeArtifactTypes[input.ArtifactType] || !safeArtifactEncodings[input.ContentEncoding] {
		return Artifact{}, errors.New("invalid artifact identity, type or encoding")
	}
	content := []byte(input.Content)
	if len(content) == 0 || len(content) > maxArtifactBytes {
		return Artifact{}, errors.New("artifact content must be between 1 byte and 900 KiB")
	}
	if input.Metadata == nil {
		input.Metadata = map[string]any{}
	}
	if input.CreatedBy == "" {
		input.CreatedBy = "owner"
	}
	input.TrustLevel = normalizeTrust(input.TrustLevel, input.Verified)
	if input.Verified && input.TrustLevel != "verified" {
		return Artifact{}, errors.New("verified artifact must use verified trust level")
	}
	if input.ArtifactType == "source_bundle" || input.ArtifactType == "synthetic_source_bundle" {
		if _, err := decodeSourceBundle(content); err != nil {
			return Artifact{}, err
		}
	}
	if input.ArtifactType == "anchor_idl" {
		var object map[string]any
		if json.Unmarshal(content, &object) != nil || object == nil {
			return Artifact{}, errors.New("anchor_idl content must be a JSON object")
		}
	}
	contentHash := hashValue(content)
	ref := prefixedID("KDA1-", map[string]any{"program": input.ProgramID, "network": input.Network, "type": input.ArtifactType, "hash": contentHash})
	metadata, _ := json.Marshal(input.Metadata)
	row := Artifact{ArtifactRef: ref, ProgramID: input.ProgramID, Network: input.Network, ArtifactType: input.ArtifactType,
		SourceURI: strings.TrimSpace(input.SourceURI), SourceCommit: strings.TrimSpace(input.SourceCommit), Framework: strings.TrimSpace(input.Framework),
		FrameworkVersion: strings.TrimSpace(input.FrameworkVersion), RuntimeVersion: strings.TrimSpace(input.RuntimeVersion), ContentHash: contentHash,
		ContentEncoding: input.ContentEncoding, Content: content, Metadata: input.Metadata, TrustLevel: input.TrustLevel, Verified: input.Verified,
		CreatedBy: input.CreatedBy, CreatedAt: time.Now().UTC()}
	_, err := db.ExecContext(ctx, `INSERT INTO defense_program_artifacts
		(artifact_ref,program_id,network,artifact_type,source_uri,source_commit,framework,framework_version,runtime_version,content_hash,content_encoding,content_bytes,metadata,trust_level,verified,created_by,created_at)
		VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),NULLIF($9,''),$10,$11,$12,$13::jsonb,$14,$15,$16,$17)
		ON CONFLICT (artifact_ref) DO NOTHING`, ref, row.ProgramID, row.Network, row.ArtifactType, row.SourceURI, row.SourceCommit, row.Framework,
		row.FrameworkVersion, row.RuntimeVersion, row.ContentHash, row.ContentEncoding, row.Content, string(metadata), row.TrustLevel, row.Verified, row.CreatedBy, row.CreatedAt)
	return row, err
}

func LoadArtifact(ctx context.Context, db *sql.DB, ref string) (Artifact, error) {
	if db == nil {
		return Artifact{}, errors.New("database unavailable")
	}
	var row Artifact
	var metadata []byte
	err := db.QueryRowContext(ctx, `SELECT artifact_ref,program_id,network,artifact_type,COALESCE(source_uri,''),COALESCE(source_commit,''),
		COALESCE(framework,''),COALESCE(framework_version,''),COALESCE(runtime_version,''),content_hash,content_encoding,content_bytes,metadata,
		trust_level,verified,created_by,created_at FROM defense_program_artifacts WHERE artifact_ref=$1`, strings.TrimSpace(ref)).Scan(
		&row.ArtifactRef, &row.ProgramID, &row.Network, &row.ArtifactType, &row.SourceURI, &row.SourceCommit, &row.Framework, &row.FrameworkVersion,
		&row.RuntimeVersion, &row.ContentHash, &row.ContentEncoding, &row.Content, &metadata, &row.TrustLevel, &row.Verified, &row.CreatedBy, &row.CreatedAt)
	if err != nil {
		return Artifact{}, err
	}
	_ = json.Unmarshal(metadata, &row.Metadata)
	if hashValue(row.Content) != row.ContentHash {
		return Artifact{}, errors.New("artifact content hash mismatch")
	}
	return row, nil
}

func ListArtifacts(ctx context.Context, db *sql.DB, programID, network string, limit int) ([]ArtifactSummary, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	programID = strings.TrimSpace(programID)
	network = normalizedNetwork(network)
	rows, err := db.QueryContext(ctx, `SELECT artifact_ref,program_id,artifact_type,content_hash,trust_level,verified,created_at
		FROM defense_program_artifacts WHERE ($1='' OR program_id=$1) AND network=$2 ORDER BY created_at DESC LIMIT $3`, programID, network, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ArtifactSummary{}
	for rows.Next() {
		var item ArtifactSummary
		if rows.Scan(&item.ArtifactRef, &item.ProgramID, &item.ArtifactType, &item.ContentHash, &item.TrustLevel, &item.Verified, &item.CreatedAt) == nil {
			out = append(out, item)
		}
	}
	return out, rows.Err()
}

func StoreKnowledge(ctx context.Context, db *sql.DB, input KnowledgeInput) (KnowledgeDocument, error) {
	if db == nil {
		return KnowledgeDocument{}, errors.New("database unavailable")
	}
	input.Title = strings.TrimSpace(input.Title)
	input.Body = strings.TrimSpace(input.Body)
	if input.Title == "" || input.Body == "" || len(input.Body) > maxArtifactBytes {
		return KnowledgeDocument{}, errors.New("knowledge title/body invalid")
	}
	if input.Metadata == nil {
		input.Metadata = map[string]any{}
	}
	if input.Tags == nil {
		input.Tags = []string{}
	}
	if input.CreatedBy == "" {
		input.CreatedBy = "owner"
	}
	input.TrustLevel = normalizeTrust(input.TrustLevel, false)
	hash := hashValue([]byte(input.Title + "\n" + input.Body))
	ref := prefixedID("KDK1-", map[string]any{"hash": hash, "framework": input.Framework, "version": input.FrameworkVersion})
	tags, _ := json.Marshal(uniqueStrings(input.Tags))
	metadata, _ := json.Marshal(input.Metadata)
	embedding := pqFloatArray(input.Embedding)
	now := time.Now().UTC()
	_, err := db.ExecContext(ctx, `INSERT INTO defense_knowledge_documents
		(document_ref,title,body,source_uri,source_commit,source_hash,framework,framework_version,runtime_version,trust_level,tags,embedding_model,embedding,metadata,created_by,created_at)
		VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,NULLIF($7,''),NULLIF($8,''),NULLIF($9,''),$10,$11::jsonb,NULLIF($12,''),$13,$14::jsonb,$15,$16)
		ON CONFLICT (document_ref) DO NOTHING`, ref, input.Title, input.Body, strings.TrimSpace(input.SourceURI), strings.TrimSpace(input.SourceCommit), hash,
		strings.TrimSpace(input.Framework), strings.TrimSpace(input.FrameworkVersion), strings.TrimSpace(input.RuntimeVersion), input.TrustLevel, string(tags),
		strings.TrimSpace(input.EmbeddingModel), embedding, string(metadata), input.CreatedBy, now)
	return KnowledgeDocument{DocumentRef: ref, Title: input.Title, Body: input.Body, SourceURI: input.SourceURI, SourceCommit: input.SourceCommit, SourceHash: hash,
		Framework: input.Framework, FrameworkVersion: input.FrameworkVersion, RuntimeVersion: input.RuntimeVersion, TrustLevel: input.TrustLevel, Tags: uniqueStrings(input.Tags),
		EmbeddingModel: input.EmbeddingModel, Metadata: input.Metadata, CreatedAt: now}, err
}

func SearchKnowledge(ctx context.Context, db *sql.DB, query, framework string, queryEmbedding []float64, limit int) ([]KnowledgeDocument, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return []KnowledgeDocument{}, nil
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := db.QueryContext(ctx, `SELECT document_ref,title,body,COALESCE(source_uri,''),COALESCE(source_commit,''),source_hash,COALESCE(framework,''),
		COALESCE(framework_version,''),COALESCE(runtime_version,''),trust_level,tags,COALESCE(embedding_model,''),embedding,metadata,created_at
		FROM defense_knowledge_documents WHERE ($2='' OR framework=$2) AND to_tsvector('simple',title||' '||body) @@ plainto_tsquery('simple',$1)
		ORDER BY ts_rank(to_tsvector('simple',title||' '||body),plainto_tsquery('simple',$1)) DESC,created_at DESC LIMIT $3`, query, strings.TrimSpace(framework), maxInt(limit*5, 50))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []KnowledgeDocument{}
	for rows.Next() {
		var d KnowledgeDocument
		var tags, meta []byte
		var embedding []float64
		if rows.Scan(&d.DocumentRef, &d.Title, &d.Body, &d.SourceURI, &d.SourceCommit, &d.SourceHash, &d.Framework, &d.FrameworkVersion, &d.RuntimeVersion, &d.TrustLevel, &tags, &d.EmbeddingModel, pqFloatArrayScanner{dest: &embedding}, &meta, &d.CreatedAt) != nil {
			continue
		}
		_ = json.Unmarshal(tags, &d.Tags)
		_ = json.Unmarshal(meta, &d.Metadata)
		if len(queryEmbedding) > 0 && len(embedding) == len(queryEmbedding) {
			d.Similarity = cosine(queryEmbedding, embedding)
		}
		out = append(out, d)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Similarity > out[j].Similarity })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, rows.Err()
}

// AttachArtifactInventory enriches the shadow runtime without granting verdict authority.
func AttachArtifactInventory(ctx context.Context, db *sql.DB, report *RuntimeReport) {
	if db == nil || report == nil || len(report.ToolInvocations) == 0 {
		return
	}
	programs := stringSlice(report.ToolInvocations[0].Output["program_ids"])
	inventory := map[string][]ArtifactSummary{}
	for _, programID := range programs {
		items, err := ListArtifacts(ctx, db, programID, report.Network, 50)
		if err == nil {
			inventory[programID] = items
		}
	}
	hasSource, hasIDL, hasBytecode := false, false, false
	for _, items := range inventory {
		for _, item := range items {
			switch item.ArtifactType {
			case "source_bundle", "source_manifest":
				hasSource = true
			case "anchor_idl":
				hasIDL = true
			case "sbpf_bytecode", "sbpf_manifest":
				hasBytecode = true
			}
		}
	}
	report.ToolInvocations[0].Output["artifact_inventory"] = inventory
	report.ToolInvocations[0].Output["source_artifact_status"] = availability(hasSource)
	report.ToolInvocations[0].Output["idl_artifact_status"] = availability(hasIDL)
	report.ToolInvocations[0].Output["bytecode_artifact_status"] = availability(hasBytecode)
	if hasSource || hasIDL || hasBytecode {
		report.Status = RuntimeObserved
		if len(report.Agents) > 1 {
			report.Agents[1].Status = RuntimeObserved
			report.Agents[1].Limitations = []string{"Artifacts are available; a separate explicit Program Lab run is required before any finding is created."}
		}
	}
	report.ToolInvocations[0].OutputHash = hashValue(report.ToolInvocations[0].Output)
	report.ReportHash = reportHash(*report)
}

// Graph and Finding are immutable evidence records produced by deterministic analyzers.
type GraphNode struct {
	NodeRef, ProgramID, Network, NodeType, NodeKey, Label, SourceArtifactRef, EvidenceStatus string
	Properties                                                                               map[string]any
}
type GraphEdge struct {
	EdgeRef, ProgramID, Network, FromNodeRef, ToNodeRef, Relation, SourceArtifactRef, EvidenceStatus string
	Properties                                                                                       map[string]any
}
type Finding struct {
	FindingRef        string         `json:"finding_ref"`
	ProgramID         string         `json:"program_id"`
	Network           string         `json:"network"`
	RuleID            string         `json:"rule_id"`
	Title             string         `json:"title"`
	Severity          string         `json:"severity"`
	Confidence        string         `json:"confidence"`
	LifecycleStatus   string         `json:"lifecycle_status"`
	SourceArtifactRef string         `json:"source_artifact_ref"`
	Location          map[string]any `json:"location"`
	EvidenceRefs      []string       `json:"evidence_refs"`
	CounterEvidence   []string       `json:"counter_evidence"`
	Limitations       []string       `json:"limitations"`
	Details           map[string]any `json:"details"`
	VerdictAuthority  bool           `json:"verdict_authority"`
}
type LabReport struct {
	ProgramID       string      `json:"program_id"`
	Network         string      `json:"network"`
	ArtifactRef     string      `json:"artifact_ref"`
	DetectorVersion string      `json:"detector_version"`
	Nodes           []GraphNode `json:"nodes"`
	Edges           []GraphEdge `json:"edges"`
	Findings        []Finding   `json:"findings"`
	Limitations     []string    `json:"limitations"`
	ReportHash      string      `json:"report_hash"`
}

func AnalyzeArtifact(artifact Artifact) (LabReport, error) {
	report := LabReport{ProgramID: artifact.ProgramID, Network: artifact.Network, ArtifactRef: artifact.ArtifactRef, DetectorVersion: DetectorVersion, Nodes: []GraphNode{}, Edges: []GraphEdge{}, Findings: []Finding{}, Limitations: []string{"Static findings are hypotheses or observed review surfaces; they cannot alter the signed Unified Radar verdict."}}
	programNode := newNode(artifact, "program", artifact.ProgramID, artifact.ProgramID, map[string]any{"framework": artifact.Framework, "framework_version": artifact.FrameworkVersion})
	report.Nodes = append(report.Nodes, programNode)
	switch artifact.ArtifactType {
	case "source_bundle", "synthetic_source_bundle":
		bundle, err := decodeSourceBundle(artifact.Content)
		if err != nil {
			return report, err
		}
		analyzeSourceBundle(artifact, bundle, &report, programNode)
	case "anchor_idl":
		analyzeIDL(artifact, &report, programNode)
	default:
		report.Limitations = append(report.Limitations, "This artifact type is inventory-only in detector v1.")
	}
	report.ReportHash = hashValue(map[string]any{"program": report.ProgramID, "artifact": report.ArtifactRef, "nodes": report.Nodes, "edges": report.Edges, "findings": report.Findings, "detector": report.DetectorVersion})
	return report, nil
}

func PersistLabReport(ctx context.Context, db *sql.DB, report LabReport) error {
	if db == nil {
		return errors.New("database unavailable")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, n := range report.Nodes {
		props, _ := json.Marshal(n.Properties)
		_, err = tx.ExecContext(ctx, `INSERT INTO defense_program_graph_nodes(node_ref,program_id,network,node_type,node_key,label,properties,source_artifact_ref,evidence_status) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9) ON CONFLICT(node_ref) DO NOTHING`, n.NodeRef, n.ProgramID, n.Network, n.NodeType, n.NodeKey, n.Label, string(props), n.SourceArtifactRef, n.EvidenceStatus)
		if err != nil {
			return err
		}
	}
	for _, e := range report.Edges {
		props, _ := json.Marshal(e.Properties)
		_, err = tx.ExecContext(ctx, `INSERT INTO defense_program_graph_edges(edge_ref,program_id,network,from_node_ref,to_node_ref,relation,properties,source_artifact_ref,evidence_status) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9) ON CONFLICT(edge_ref) DO NOTHING`, e.EdgeRef, e.ProgramID, e.Network, e.FromNodeRef, e.ToNodeRef, e.Relation, string(props), e.SourceArtifactRef, e.EvidenceStatus)
		if err != nil {
			return err
		}
	}
	for _, f := range report.Findings {
		loc, _ := json.Marshal(f.Location)
		ev, _ := json.Marshal(f.EvidenceRefs)
		ce, _ := json.Marshal(f.CounterEvidence)
		lim, _ := json.Marshal(f.Limitations)
		det, _ := json.Marshal(f.Details)
		_, err = tx.ExecContext(ctx, `INSERT INTO defense_program_findings(finding_ref,program_id,network,rule_id,title,severity,confidence,lifecycle_status,source_artifact_ref,location,evidence_refs,counter_evidence,limitations,details,verdict_authority) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12::jsonb,$13::jsonb,$14::jsonb,false) ON CONFLICT(finding_ref) DO NOTHING`, f.FindingRef, f.ProgramID, f.Network, f.RuleID, f.Title, f.Severity, f.Confidence, f.LifecycleStatus, f.SourceArtifactRef, string(loc), string(ev), string(ce), string(lim), string(det))
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func analyzeSourceBundle(a Artifact, bundle map[string]string, r *LabReport, program GraphNode) {
	paths := make([]string, 0, len(bundle))
	for p := range bundle {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, path := range paths {
		content := bundle[path]
		instructions := regexp.MustCompile(`(?m)pub\s+fn\s+([A-Za-z0-9_]+)\s*\(`).FindAllStringSubmatch(content, -1)
		for _, m := range instructions {
			node := newNode(a, "instruction", path+":"+m[1], m[1], map[string]any{"path": path})
			r.Nodes = append(r.Nodes, node)
			r.Edges = append(r.Edges, newEdge(a, program, node, "HAS_INSTRUCTION", map[string]any{}))
		}
		runDetector(a, r, path, content, "KPS-S001", "UncheckedAccount without CHECK rationale", "medium", regexp.MustCompile(`UncheckedAccount\s*<'info>`), func(text string) bool { return !strings.Contains(text, "CHECK:") }, "UncheckedAccount requires explicit manual validation; this static observation is not proof of exploitability.")
		runDetector(a, r, path, content, "KPS-S002", "Unsafe Rust block present", "medium", regexp.MustCompile(`\bunsafe\s*\{`), nil, "Unsafe code expands the review surface; reachability and memory impact require reproduction.")
		runDetector(a, r, path, content, "KPS-S003", "invoke_unchecked call present", "high", regexp.MustCompile(`\binvoke_unchecked\s*\(`), nil, "Unchecked invocation can bypass runtime assumptions; account and caller constraints must be verified.")
		runDetector(a, r, path, content, "KPS-S004", "remaining_accounts consumed", "medium", regexp.MustCompile(`remaining_accounts`), nil, "Dynamic remaining accounts require explicit owner, key and mutability validation.")
		runDetector(a, r, path, content, "KPS-S005", "init_if_needed surface present", "medium", regexp.MustCompile(`init_if_needed`), nil, "Initialization state and discriminator invariants require review for reinitialization paths.")
		runDetector(a, r, path, content, "KPS-S006", "realloc surface present", "medium", regexp.MustCompile(`\brealloc\s*=`), nil, "Reallocation payer, zeroing and size invariants require review.")
		runDetector(a, r, path, content, "KPS-S007", "Token-2022 control extension referenced", "medium", regexp.MustCompile(`(?i)permanent_delegate|transfer_hook|transfer_fee`), nil, "Token-2022 authority and hook behavior must be bound to verified mint-extension state.")
		runDetector(a, r, path, content, "KPS-S008", "panic-prone unwrap/expect in program path", "low", regexp.MustCompile(`\.(unwrap|expect)\s*\(`), nil, "A panic candidate is availability context, not proof of fund loss.")
	}
}

func analyzeIDL(a Artifact, r *LabReport, program GraphNode) {
	var root map[string]any
	if json.Unmarshal(a.Content, &root) != nil {
		r.Limitations = append(r.Limitations, "IDL JSON could not be parsed.")
		return
	}
	list, _ := root["instructions"].([]any)
	for _, raw := range list {
		m, _ := raw.(map[string]any)
		name := fmt.Sprint(m["name"])
		if name == "" {
			continue
		}
		ins := newNode(a, "instruction", "idl:"+name, name, map[string]any{"source": "anchor_idl"})
		r.Nodes = append(r.Nodes, ins)
		r.Edges = append(r.Edges, newEdge(a, program, ins, "HAS_INSTRUCTION", map[string]any{}))
		accounts, _ := m["accounts"].([]any)
		for _, ar := range accounts {
			am, _ := ar.(map[string]any)
			an := fmt.Sprint(am["name"])
			if an == "" {
				continue
			}
			acc := newNode(a, "account", "idl:"+name+":"+an, an, am)
			r.Nodes = append(r.Nodes, acc)
			r.Edges = append(r.Edges, newEdge(a, ins, acc, "USES_ACCOUNT", map[string]any{}))
		}
	}
}

func runDetector(a Artifact, r *LabReport, path, content, rule, title, severity string, re *regexp.Regexp, predicate func(string) bool, limitation string) {
	matches := re.FindAllStringIndex(content, -1)
	for _, m := range matches {
		start := maxInt(0, m[0]-160)
		end := minInt(len(content), m[1]+160)
		contextText := content[start:end]
		if predicate != nil && !predicate(contextText) {
			continue
		}
		line := 1 + strings.Count(content[:m[0]], "\n")
		location := map[string]any{"path": path, "line": line, "match": content[m[0]:m[1]]}
		ref := prefixedID("KDF1-", map[string]any{"artifact": a.ArtifactRef, "rule": rule, "path": path, "line": line})
		r.Findings = append(r.Findings, Finding{FindingRef: ref, ProgramID: a.ProgramID, Network: a.Network, RuleID: rule, Title: title, Severity: severity, Confidence: "observed", LifecycleStatus: "hypothesis", SourceArtifactRef: a.ArtifactRef, Location: location, EvidenceRefs: []string{"artifact:" + a.ArtifactRef, "hash:" + a.ContentHash}, CounterEvidence: []string{}, Limitations: []string{limitation, "No runtime reachability or asset impact has been established."}, Details: map[string]any{"detector_version": DetectorVersion}, VerdictAuthority: false})
	}
}

func newNode(a Artifact, kind, key, label string, props map[string]any) GraphNode {
	ref := prefixedID("KDN1-", map[string]any{"artifact": a.ArtifactRef, "type": kind, "key": key})
	return GraphNode{NodeRef: ref, ProgramID: a.ProgramID, Network: a.Network, NodeType: kind, NodeKey: key, Label: label, Properties: props, SourceArtifactRef: a.ArtifactRef, EvidenceStatus: "observed"}
}
func newEdge(a Artifact, from, to GraphNode, relation string, props map[string]any) GraphEdge {
	ref := prefixedID("KDE1-", map[string]any{"artifact": a.ArtifactRef, "from": from.NodeRef, "to": to.NodeRef, "relation": relation})
	return GraphEdge{EdgeRef: ref, ProgramID: a.ProgramID, Network: a.Network, FromNodeRef: from.NodeRef, ToNodeRef: to.NodeRef, Relation: relation, Properties: props, SourceArtifactRef: a.ArtifactRef, EvidenceStatus: "observed"}
}

// Sandbox verification is local-only and command allowlisted. It cannot sign or send a transaction.
type CommandResult struct {
	Command    string `json:"command"`
	Status     string `json:"status"`
	ExitCode   int    `json:"exit_code"`
	Output     string `json:"output"`
	DurationMS int64  `json:"duration_ms"`
}
type VerificationReport struct {
	VerificationRef   string          `json:"verification_ref"`
	ProgramID         string          `json:"program_id"`
	Network           string          `json:"network"`
	FindingRef        string          `json:"finding_ref,omitempty"`
	SourceArtifactRef string          `json:"source_artifact_ref"`
	PatchRef          string          `json:"patch_ref,omitempty"`
	ExecutionMode     string          `json:"execution_mode"`
	Status            string          `json:"status"`
	Commands          []string        `json:"commands"`
	Results           []CommandResult `json:"command_results"`
	InputHash         string          `json:"input_hash"`
	OutputHash        string          `json:"output_hash"`
	Limitations       []string        `json:"limitations"`
	CanExecuteMainnet bool            `json:"can_execute_mainnet"`
}

func VerifyBundle(ctx context.Context, a Artifact, findingRef, patchRef string, replacements map[string]string, commands []string, enabled bool) (VerificationReport, error) {
	inputHash := hashValue(map[string]any{"artifact": a.ArtifactRef, "finding": findingRef, "patch": patchRef, "replacements": replacements, "commands": commands})
	report := VerificationReport{ProgramID: a.ProgramID, Network: a.Network, FindingRef: findingRef, SourceArtifactRef: a.ArtifactRef, PatchRef: patchRef, ExecutionMode: "blocked", Status: "blocked", Commands: commands, Results: []CommandResult{}, InputHash: inputHash, Limitations: []string{}, CanExecuteMainnet: false}
	if !enabled {
		report.Limitations = []string{"KOSCHEI_DEFENSE_SANDBOX_ENABLED is false. No command was executed."}
		return finishVerification(report), nil
	}
	bundle, err := decodeSourceBundle(a.Content)
	if err != nil {
		return report, err
	}
	for p, c := range replacements {
		clean, err := safeRelativePath(p)
		if err != nil {
			return report, err
		}
		bundle[clean] = c
	}
	root, err := os.MkdirTemp("", "koschei-defense-")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(root)
	if err = materializeBundle(root, bundle); err != nil {
		return report, err
	}
	report.ExecutionMode = "local_sandbox"
	overall := "passed"
	for _, command := range commands {
		args, ok := allowedCommand(command)
		if !ok {
			report.Results = append(report.Results, CommandResult{Command: command, Status: "blocked", ExitCode: -1, Output: "command is not allowlisted"})
			overall = "partial"
			continue
		}
		started := time.Now()
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Dir = root
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + root, "CARGO_HOME=" + filepath.Join(root, ".cargo"), "RUSTUP_HOME=" + filepath.Join(root, ".rustup"), "CARGO_BUILD_JOBS=" + strconv.Itoa(runtimecfg.Load().WorkerMaxBuildThreads), "KOSCHEI_SANDBOX=1"}
		var output bytes.Buffer
		cmd.Stdout = &limitedWriter{w: &output, n: maxSandboxOutput}
		cmd.Stderr = &limitedWriter{w: &output, n: maxSandboxOutput}
		err := cmd.Run()
		exit := 0
		status := "passed"
		if err != nil {
			status = "failed"
			overall = "failed"
			if e, ok := err.(*exec.ExitError); ok {
				exit = e.ExitCode()
			} else {
				exit = -1
			}
		}
		report.Results = append(report.Results, CommandResult{Command: command, Status: status, ExitCode: exit, Output: output.String(), DurationMS: time.Since(started).Milliseconds()})
	}
	if len(commands) == 0 {
		overall = "partial"
		report.Limitations = append(report.Limitations, "No verification command was requested.")
	}
	report.Status = overall
	return finishVerification(report), nil
}

func PersistVerification(ctx context.Context, db *sql.DB, r VerificationReport) error {
	if db == nil {
		return errors.New("database unavailable")
	}
	commands, _ := json.Marshal(r.Commands)
	results, _ := json.Marshal(r.Results)
	limitations, _ := json.Marshal(r.Limitations)
	_, err := db.ExecContext(ctx, `INSERT INTO defense_verification_runs(verification_ref,program_id,network,finding_ref,source_artifact_ref,patch_ref,execution_mode,status,commands,command_results,input_hash,output_hash,limitations,can_execute_mainnet) VALUES($1,$2,$3,NULLIF($4,''),$5,NULLIF($6,''),$7,$8,$9::jsonb,$10::jsonb,$11,$12,$13::jsonb,false) ON CONFLICT(verification_ref) DO NOTHING`, r.VerificationRef, r.ProgramID, r.Network, r.FindingRef, r.SourceArtifactRef, r.PatchRef, r.ExecutionMode, r.Status, string(commands), string(results), r.InputHash, r.OutputHash, string(limitations))
	return err
}

func finishVerification(r VerificationReport) VerificationReport {
	r.OutputHash = hashValue(map[string]any{"status": r.Status, "results": r.Results, "limitations": r.Limitations})
	r.VerificationRef = prefixedID("KDV1-", map[string]any{"input": r.InputHash, "output": r.OutputHash})
	return r
}
func allowedCommand(command string) ([]string, bool) {
	command = strings.Join(strings.Fields(command), " ")
	allowed := map[string][]string{"cargo test": {"cargo", "test"}, "cargo test --workspace --all-targets": {"cargo", "test", "--workspace", "--all-targets"}, "cargo build-sbf": {"cargo", "build-sbf"}, "anchor test --skip-local-validator": {"anchor", "test", "--skip-local-validator"}, "trident fuzz run": {"trident", "fuzz", "run"}}
	v, ok := allowed[command]
	return v, ok
}

// SyntheticMutation creates non-production hard-negative or vulnerable training candidates.
func SyntheticMutation(a Artifact, mutation string) (ArtifactInput, error) {
	bundle, err := decodeSourceBundle(a.Content)
	if err != nil {
		return ArtifactInput{}, err
	}
	changed := false
	for p, c := range bundle {
		switch mutation {
		case "replace_signer_with_unchecked":
			next := strings.ReplaceAll(c, "Signer<'info>", "UncheckedAccount<'info>")
			changed = changed || next != c
			bundle[p] = next
		case "remove_has_one_constraint":
			re := regexp.MustCompile(`,?\s*has_one\s*=\s*[A-Za-z0-9_]+`)
			next := re.ReplaceAllString(c, "")
			changed = changed || next != c
			bundle[p] = next
		case "remove_owner_constraint":
			re := regexp.MustCompile(`,?\s*owner\s*=\s*[^,\)]+`)
			next := re.ReplaceAllString(c, "")
			changed = changed || next != c
			bundle[p] = next
		default:
			return ArtifactInput{}, errors.New("unsupported synthetic mutation")
		}
	}
	if !changed {
		return ArtifactInput{}, errors.New("mutation found no applicable source pattern")
	}
	encoded, _ := json.Marshal(bundle)
	return ArtifactInput{ProgramID: a.ProgramID, Network: a.Network, ArtifactType: "synthetic_source_bundle", SourceURI: a.SourceURI, SourceCommit: a.SourceCommit, Framework: a.Framework, FrameworkVersion: a.FrameworkVersion, RuntimeVersion: a.RuntimeVersion, ContentEncoding: "json", Content: string(encoded), Metadata: map[string]any{"parent_artifact_ref": a.ArtifactRef, "mutation": mutation, "production_eligible": false}, TrustLevel: "synthetic", Verified: false, CreatedBy: "owner"}, nil
}

type EvaluationMetrics struct {
	TruePositive  int     `json:"true_positive"`
	FalsePositive int     `json:"false_positive"`
	FalseNegative int     `json:"false_negative"`
	TrueNegative  int     `json:"true_negative"`
	Precision     float64 `json:"precision"`
	Recall        float64 `json:"recall"`
	Passed        bool    `json:"passed"`
}

func EvaluateRules(expected, expectedAbsent, observed []string) EvaluationMetrics {
	e := setStrings(expected)
	a := setStrings(expectedAbsent)
	o := setStrings(observed)
	m := EvaluationMetrics{}
	for r := range e {
		if o[r] {
			m.TruePositive++
		} else {
			m.FalseNegative++
		}
	}
	for r := range o {
		if !e[r] {
			m.FalsePositive++
		}
	}
	for r := range a {
		if !o[r] {
			m.TrueNegative++
		}
	}
	if m.TruePositive+m.FalsePositive > 0 {
		m.Precision = float64(m.TruePositive) / float64(m.TruePositive+m.FalsePositive)
	}
	if m.TruePositive+m.FalseNegative > 0 {
		m.Recall = float64(m.TruePositive) / float64(m.TruePositive+m.FalseNegative)
	}
	m.Passed = m.FalseNegative == 0 && m.FalsePositive == 0
	return m
}

func decodeSourceBundle(content []byte) (map[string]string, error) {
	var bundle map[string]string
	if json.Unmarshal(content, &bundle) != nil || len(bundle) == 0 {
		return nil, errors.New("source_bundle content must be a non-empty JSON object of relative path to UTF-8 source")
	}
	total := 0
	cleaned := map[string]string{}
	for p, c := range bundle {
		clean, err := safeRelativePath(p)
		if err != nil {
			return nil, err
		}
		total += len(c)
		if total > maxArtifactBytes {
			return nil, errors.New("source bundle exceeds 900 KiB")
		}
		cleaned[clean] = c
	}
	return cleaned, nil
}
func materializeBundle(root string, bundle map[string]string) error {
	for p, c := range bundle {
		clean, err := safeRelativePath(p)
		if err != nil {
			return err
		}
		full := filepath.Join(root, clean)
		if err = os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			return err
		}
		if err = os.WriteFile(full, []byte(c), 0600); err != nil {
			return err
		}
	}
	return nil
}
func safeRelativePath(p string) (string, error) {
	p = filepath.ToSlash(strings.TrimSpace(p))
	clean := filepath.Clean(p)
	if p == "" || filepath.IsAbs(clean) || clean == "." || strings.HasPrefix(clean, "..") || strings.Contains(clean, "/.git/") || strings.HasPrefix(clean, ".git/") {
		return "", errors.New("unsafe artifact path")
	}
	return clean, nil
}
func normalizeTrust(v string, verified bool) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if verified {
		return "verified"
	}
	switch v {
	case "verified", "observed", "unverified", "synthetic":
		return v
	}
	return "unverified"
}
func availability(v bool) string {
	if v {
		return "attached"
	}
	return "not_attached"
}
func uniqueStrings(in []string) []string {
	set := map[string]bool{}
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" && !set[v] {
			set[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
func stringSlice(v any) []string {
	out := []string{}
	switch x := v.(type) {
	case []string:
		return uniqueStrings(x)
	case []any:
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	}
	return uniqueStrings(out)
}
func setStrings(in []string) map[string]bool {
	m := map[string]bool{}
	for _, v := range in {
		if strings.TrimSpace(v) != "" {
			m[strings.TrimSpace(v)] = true
		}
	}
	return m
}
func cosine(a, b []float64) float64 {
	var dot, aa, bb float64
	for i := range a {
		dot += a[i] * b[i]
		aa += a[i] * a[i]
		bb += b[i] * b[i]
	}
	if aa == 0 || bb == 0 {
		return 0
	}
	return dot / (math.Sqrt(aa) * math.Sqrt(bb))
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type limitedWriter struct {
	w *bytes.Buffer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	if len(p) > l.n {
		_, _ = l.w.Write(p[:l.n])
		l.n = 0
		return len(p), nil
	}
	_, _ = l.w.Write(p)
	l.n -= len(p)
	return len(p), nil
}

// PostgreSQL float array helpers avoid a new dependency.
type pqFloatArray []float64

func (a pqFloatArray) Value() (driver.Value, error) {
	if len(a) == 0 {
		return nil, nil
	}
	parts := make([]string, len(a))
	for i, v := range a {
		parts[i] = fmt.Sprintf("%.17g", v)
	}
	return "{" + strings.Join(parts, ",") + "}", nil
}

type pqFloatArrayScanner struct{ dest *[]float64 }

func (s pqFloatArrayScanner) Scan(src any) error {
	if src == nil {
		*s.dest = nil
		return nil
	}
	var text string
	switch value := src.(type) {
	case string:
		text = value
	case []byte:
		text = string(value)
	default:
		text = fmt.Sprint(value)
	}
	text = strings.Trim(text, "{}")
	if text == "" {
		*s.dest = nil
		return nil
	}
	parts := strings.Split(text, ",")
	out := make([]float64, 0, len(parts))
	for _, part := range parts {
		var value float64
		if _, err := fmt.Sscan(strings.TrimSpace(part), &value); err != nil {
			return err
		}
		out = append(out, value)
	}
	*s.dest = out
	return nil
}
