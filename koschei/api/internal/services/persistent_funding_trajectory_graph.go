package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

const PersistentFundingTrajectoryGraphVersion = "koschei-persistent-funding-trajectory-graph-v1"

type PersistentFundingTrajectoryNode struct {
	ID       string         `json:"id"`
	Kind     string         `json:"kind"`
	Role     string         `json:"role"`
	Metadata map[string]any `json:"metadata"`
}

type PersistentFundingTrajectoryEdge struct {
	SourceID       string         `json:"source_id"`
	SourceKind     string         `json:"source_kind"`
	TargetID       string         `json:"target_id"`
	TargetKind     string         `json:"target_kind"`
	Relation       string         `json:"relation"`
	EvidenceState  string         `json:"evidence_state"`
	EvidenceKind   string         `json:"evidence_kind"`
	Signature      string         `json:"signature,omitempty"`
	Slot           int64          `json:"slot,omitempty"`
	ObservedAt     string         `json:"observed_at"`
	SourceProvider string         `json:"source_provider"`
	Metadata       map[string]any `json:"metadata"`
}

type PersistentFundingTrajectoryGraph struct {
	Version                   string                            `json:"version"`
	Network                   string                            `json:"network"`
	SubjectWallet             string                            `json:"subject_wallet"`
	Available                 bool                              `json:"available"`
	Complete                  bool                              `json:"complete"`
	Status                    string                            `json:"status"`
	NodeCount                 int                               `json:"node_count"`
	EdgeCount                 int                               `json:"edge_count"`
	FundingEdgeCount          int                               `json:"funding_edge_count"`
	CreationEdgeCount         int                               `json:"creation_edge_count"`
	LifecycleEdgeCount        int                               `json:"lifecycle_edge_count"`
	SignedVerdictEdgeCount    int                               `json:"signed_verdict_edge_count"`
	ExitEdgeCount             int                               `json:"exit_edge_count"`
	VerifiedEvidenceEdgeCount int                               `json:"verified_evidence_edge_count"`
	ObservedEvidenceEdgeCount int                               `json:"observed_evidence_edge_count"`
	SignedArtifactEdgeCount   int                               `json:"signed_artifact_edge_count"`
	Nodes                     []PersistentFundingTrajectoryNode `json:"nodes"`
	Edges                     []PersistentFundingTrajectoryEdge `json:"edges"`
	EvidenceHashSHA256        string                            `json:"evidence_hash_sha256"`
	VerdictAuthority          bool                              `json:"verdict_authority"`
	SameOperatorClaim         bool                              `json:"same_operator_claim"`
	RealWorldIdentityClaim    bool                              `json:"real_world_identity_claim"`
	RugClaim                  bool                              `json:"rug_claim"`
	WrongdoingClaim           bool                              `json:"wrongdoing_claim"`
	Limitations               []string                          `json:"limitations"`
}

type persistentFundingTrajectoryRow struct {
	SourceID       string
	SourceKind     string
	SourceRole     string
	TargetID       string
	TargetKind     string
	TargetRole     string
	Relation       string
	EvidenceState  string
	EvidenceKind   string
	Signature      string
	Slot           int64
	ObservedAt     time.Time
	SourceProvider string
	Metadata       []byte
}

func NewPersistentFundingTrajectoryUnavailableGraph(subject, network, status, limitation string) PersistentFundingTrajectoryGraph {
	if strings.TrimSpace(status) == "" {
		status = "source_unavailable"
	}
	out := PersistentFundingTrajectoryGraph{
		Version:       PersistentFundingTrajectoryGraphVersion,
		Network:       normalizeRadarNetwork(network),
		SubjectWallet: strings.TrimSpace(subject),
		Status:        status,
		Nodes:         []PersistentFundingTrajectoryNode{},
		Edges:         []PersistentFundingTrajectoryEdge{},
		Limitations:   []string{},
	}
	if strings.TrimSpace(limitation) != "" {
		out.Limitations = append(out.Limitations, strings.TrimSpace(limitation))
	}
	out.EvidenceHashSHA256 = hashPersistentFundingTrajectoryGraph(out)
	return out
}

// LoadPersistentFundingTrajectoryGraph projects already-retained evidence into
// a time-ordered path:
//
// funding source -> funded actor -> created token -> lifecycle / signed verdict / exit evidence.
//
// It creates no new attribution or verdict. Every edge is backed by one of the
// existing persistent evidence contracts; signed verdict edges describe a signed
// Koschei artifact, while verified/observed states describe on-chain evidence.
func LoadPersistentFundingTrajectoryGraph(ctx context.Context, db *sql.DB, subject, network string, limit int) (PersistentFundingTrajectoryGraph, error) {
	subject = strings.TrimSpace(subject)
	network = normalizeRadarNetwork(network)
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	out := PersistentFundingTrajectoryGraph{
		Version:       PersistentFundingTrajectoryGraphVersion,
		Network:       network,
		SubjectWallet: subject,
		Complete:      true,
		Status:        "no_persistent_trajectory_observed",
		Nodes:         []PersistentFundingTrajectoryNode{},
		Edges:         []PersistentFundingTrajectoryEdge{},
		Limitations: []string{
			"The graph contains retained technical evidence only; shared funding does not prove common control, identity, intent or wrongdoing.",
			"inactive_or_dead lifecycle state is an availability/liquidity observation and is not a rug classification.",
			"signed_artifact means Koschei retained a signed deterministic verdict artifact; it is distinct from verified on-chain evidence.",
			"A missing edge means Koschei has no retained qualifying evidence for that relation; it is not a safety claim.",
		},
	}
	if subject == "" {
		out.Complete = false
		out.Status = "invalid_subject"
		out.Limitations = append(out.Limitations, "Subject wallet is empty; trajectory graph was not queried.")
		out.EvidenceHashSHA256 = hashPersistentFundingTrajectoryGraph(out)
		return out, nil
	}
	if db == nil {
		return NewPersistentFundingTrajectoryUnavailableGraph(subject, network, "source_unavailable", "Persistent actor database is unavailable."), nil
	}

	rows, err := db.QueryContext(ctx, persistentFundingTrajectorySQL, network, subject, limit)
	if err != nil {
		if isSecurityRadarMissingRelation(err) {
			return NewPersistentFundingTrajectoryUnavailableGraph(subject, network, "source_unavailable", "One or more persistent trajectory evidence tables are unavailable."), nil
		}
		return out, err
	}
	defer rows.Close()

	nodes := map[string]PersistentFundingTrajectoryNode{}
	for rows.Next() {
		var row persistentFundingTrajectoryRow
		if err := rows.Scan(
			&row.SourceID,
			&row.SourceKind,
			&row.SourceRole,
			&row.TargetID,
			&row.TargetKind,
			&row.TargetRole,
			&row.Relation,
			&row.EvidenceState,
			&row.EvidenceKind,
			&row.Signature,
			&row.Slot,
			&row.ObservedAt,
			&row.SourceProvider,
			&row.Metadata,
		); err != nil {
			return out, err
		}
		metadata := map[string]any{}
		if len(row.Metadata) > 0 {
			_ = json.Unmarshal(row.Metadata, &metadata)
		}
		edge := PersistentFundingTrajectoryEdge{
			SourceID:       strings.TrimSpace(row.SourceID),
			SourceKind:     strings.TrimSpace(row.SourceKind),
			TargetID:       strings.TrimSpace(row.TargetID),
			TargetKind:     strings.TrimSpace(row.TargetKind),
			Relation:       strings.TrimSpace(row.Relation),
			EvidenceState:  normalizePersistentTrajectoryEvidenceState(row.EvidenceState),
			EvidenceKind:   strings.TrimSpace(row.EvidenceKind),
			Signature:      strings.TrimSpace(row.Signature),
			Slot:           row.Slot,
			ObservedAt:     row.ObservedAt.UTC().Format(time.RFC3339Nano),
			SourceProvider: strings.TrimSpace(row.SourceProvider),
			Metadata:       metadata,
		}
		if edge.SourceID == "" || edge.TargetID == "" || edge.Relation == "" {
			continue
		}
		out.Edges = append(out.Edges, edge)
		upsertPersistentTrajectoryNode(nodes, edge.SourceID, edge.SourceKind, row.SourceRole)
		upsertPersistentTrajectoryNode(nodes, edge.TargetID, edge.TargetKind, row.TargetRole)
		switch edge.EvidenceKind {
		case "funding":
			out.FundingEdgeCount++
		case "creation":
			out.CreationEdgeCount++
		case "lifecycle":
			out.LifecycleEdgeCount++
		case "signed_verdict":
			out.SignedVerdictEdgeCount++
		case "exit_event":
			out.ExitEdgeCount++
		}
		switch edge.EvidenceState {
		case "verified":
			out.VerifiedEvidenceEdgeCount++
		case "observed":
			out.ObservedEvidenceEdgeCount++
		case "signed_artifact":
			out.SignedArtifactEdgeCount++
		}
	}
	if err := rows.Err(); err != nil {
		return out, err
	}

	for _, node := range nodes {
		out.Nodes = append(out.Nodes, node)
	}
	sort.SliceStable(out.Nodes, func(i, j int) bool {
		if out.Nodes[i].Kind != out.Nodes[j].Kind {
			return out.Nodes[i].Kind < out.Nodes[j].Kind
		}
		return out.Nodes[i].ID < out.Nodes[j].ID
	})
	sort.SliceStable(out.Edges, func(i, j int) bool {
		if out.Edges[i].ObservedAt != out.Edges[j].ObservedAt {
			return out.Edges[i].ObservedAt < out.Edges[j].ObservedAt
		}
		if out.Edges[i].SourceID != out.Edges[j].SourceID {
			return out.Edges[i].SourceID < out.Edges[j].SourceID
		}
		if out.Edges[i].Relation != out.Edges[j].Relation {
			return out.Edges[i].Relation < out.Edges[j].Relation
		}
		return out.Edges[i].TargetID < out.Edges[j].TargetID
	})
	out.NodeCount = len(out.Nodes)
	out.EdgeCount = len(out.Edges)
	out.Available = out.EdgeCount > 0
	if out.Available {
		out.Status = "persistent_trajectory_observed"
	}
	out.EvidenceHashSHA256 = hashPersistentFundingTrajectoryGraph(out)
	return out, nil
}

func upsertPersistentTrajectoryNode(nodes map[string]PersistentFundingTrajectoryNode, id, kind, role string) {
	id = strings.TrimSpace(id)
	kind = strings.TrimSpace(kind)
	role = strings.TrimSpace(role)
	if id == "" {
		return
	}
	if kind == "" {
		kind = "wallet"
	}
	key := strings.ToLower(kind + "|" + id)
	current, exists := nodes[key]
	if !exists {
		nodes[key] = PersistentFundingTrajectoryNode{ID: id, Kind: kind, Role: role, Metadata: map[string]any{}}
		return
	}
	if current.Role == "" && role != "" {
		current.Role = role
		nodes[key] = current
	}
}

func normalizePersistentTrajectoryEvidenceState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "verified":
		return "verified"
	case "signed", "signed_artifact":
		return "signed_artifact"
	default:
		return "observed"
	}
}

func hashPersistentFundingTrajectoryGraph(graph PersistentFundingTrajectoryGraph) string {
	graph.EvidenceHashSHA256 = ""
	payload, err := json.Marshal(graph)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

const persistentFundingTrajectorySQL = `
WITH raw_sources AS (
	SELECT counterpart_id AS source_wallet,true AS direct_source_of_subject
	FROM security_actor_evidence
	WHERE network=$1
	  AND actor_wallet=$2
	  AND actor_role='funded_wallet'
	  AND counterpart_kind='wallet'
	  AND relation IN ('initial_funding_in','oldest_funding_in_window')
	  AND verification_status IN ('verified','observed')
	  AND btrim(counterpart_id)<>''
	  AND counterpart_id<>actor_wallet
	UNION ALL
	SELECT $2 AS source_wallet,false AS direct_source_of_subject
	WHERE EXISTS (
		SELECT 1 FROM security_actor_evidence
		WHERE network=$1
		  AND actor_role='funded_wallet'
		  AND counterpart_kind='wallet'
		  AND counterpart_id=$2
		  AND actor_wallet<>$2
		  AND relation IN ('initial_funding_in','oldest_funding_in_window')
		  AND verification_status IN ('verified','observed')
	)
), sources AS (
	SELECT source_wallet,bool_or(direct_source_of_subject) AS direct_source_of_subject
	FROM raw_sources
	WHERE btrim(source_wallet)<>''
	GROUP BY source_wallet
), funding AS (
	SELECT
		s.source_wallet,
		s.direct_source_of_subject,
		e.actor_wallet AS funded_wallet,
		e.verification_status,
		COALESCE(e.signature,'') AS signature,
		COALESCE(e.slot,0) AS slot,
		e.observed_at,
		COALESCE(e.source,'security_actor_evidence') AS source_provider,
		e.relation AS original_relation,
		COALESCE(e.metadata,'{}'::jsonb) AS metadata
	FROM sources s
	JOIN security_actor_evidence e
	  ON e.network=$1
	 AND e.actor_role='funded_wallet'
	 AND e.counterpart_kind='wallet'
	 AND e.counterpart_id=s.source_wallet
	 AND e.actor_wallet<>s.source_wallet
	 AND e.relation IN ('initial_funding_in','oldest_funding_in_window')
	 AND e.verification_status IN ('verified','observed')
), actors AS (
	SELECT DISTINCT source_wallet,direct_source_of_subject,funded_wallet
	FROM funding
), creation AS (
	SELECT
		a.source_wallet,
		a.direct_source_of_subject,
		a.funded_wallet,
		COALESCE(NULLIF(btrim(e.token_mint),''),CASE WHEN e.counterpart_kind='token' THEN NULLIF(btrim(e.counterpart_id),'') ELSE NULL END) AS mint,
		e.verification_status,
		COALESCE(e.signature,'') AS signature,
		COALESCE(e.slot,0) AS slot,
		e.observed_at,
		COALESCE(e.source,'security_actor_evidence') AS source_provider,
		COALESCE(e.metadata,'{}'::jsonb) AS metadata
	FROM actors a
	JOIN security_actor_evidence e
	  ON e.network=$1
	 AND e.actor_wallet=a.funded_wallet
	 AND e.actor_role='creator_deployer'
	 AND e.relation='created_token'
	 AND e.verification_status IN ('verified','observed')
), tokens AS (
	SELECT DISTINCT source_wallet,direct_source_of_subject,funded_wallet,mint
	FROM creation
	WHERE mint IS NOT NULL AND btrim(mint)<>''
	UNION
	SELECT DISTINCT a.source_wallet,a.direct_source_of_subject,a.funded_wallet,l.mint
	FROM actors a
	JOIN security_actor_token_lifecycle l
	  ON l.network=$1 AND l.actor_wallet=a.funded_wallet
), trajectory AS (
	SELECT
		f.source_wallet AS source_id,'wallet'::text AS source_kind,'funding_source'::text AS source_role,
		f.funded_wallet AS target_id,'wallet'::text AS target_kind,'funded_actor'::text AS target_role,
		'funded_actor'::text AS relation,f.verification_status AS evidence_state,'funding'::text AS evidence_kind,
		f.signature,f.slot,f.observed_at,f.source_provider,
		jsonb_build_object(
			'original_relation',f.original_relation,
			'direct_source_of_subject',f.direct_source_of_subject,
			'evidence_metadata',f.metadata
		) AS metadata
	FROM funding f

	UNION ALL

	SELECT
		c.funded_wallet,'wallet','creator_deployer',
		c.mint,'token','created_token',
		'created_token',c.verification_status,'creation',
		c.signature,c.slot,c.observed_at,c.source_provider,
		jsonb_build_object(
			'funding_source_wallet',c.source_wallet,
			'direct_source_of_subject',c.direct_source_of_subject,
			'evidence_metadata',c.metadata
		)
	FROM creation c
	WHERE c.mint IS NOT NULL AND btrim(c.mint)<>''

	UNION ALL

	SELECT
		t.funded_wallet,'wallet','creator_deployer',
		t.mint,'token','creator_linked_token',
		CASE WHEN l.fate_status='inactive_or_dead' THEN 'lifecycle_inactive_or_dead' ELSE 'lifecycle_active' END,
		CASE
			WHEN l.fate_status='inactive_or_dead'
			 AND l.first_liquid_observed_at IS NOT NULL
			 AND l.current_inactive_since IS NOT NULL
			 AND l.current_inactive_since>=l.first_liquid_observed_at THEN 'verified'
			ELSE 'observed'
		END,
		'lifecycle',COALESCE(l.creation_signature,''),COALESCE(l.creation_slot,0),l.last_observed_at,
		'security_actor_token_lifecycle',
		jsonb_build_object(
			'funding_source_wallet',t.source_wallet,
			'direct_source_of_subject',t.direct_source_of_subject,
			'fate_status',l.fate_status,
			'observation_count',l.observation_count,
			'reactivation_count',l.reactivation_count,
			'first_observed_at',l.first_observed_at,
			'first_liquid_observed_at',l.first_liquid_observed_at,
			'current_inactive_since',l.current_inactive_since,
			'current_liquidity_usd',l.current_liquidity_usd,
			'current_price_usd',l.current_price_usd
		)
	FROM tokens t
	JOIN security_actor_token_lifecycle l
	  ON l.network=$1 AND l.actor_wallet=t.funded_wallet AND l.mint=t.mint

	UNION ALL

	SELECT
		t.mint,'token','creator_linked_token',
		('verdict:'||v.fingerprint),'verdict','signed_unified_verdict',
		'signed_unified_verdict','signed_artifact','signed_verdict',
		COALESCE(v.signature,''),0,v.last_seen_at,'security_unified_radar_verdicts',
		jsonb_build_object(
			'funding_source_wallet',t.source_wallet,
			'actor_wallet',t.funded_wallet,
			'grade',v.grade,
			'verdict',v.verdict,
			'ruleset_version',v.ruleset_version,
			'actor_ruleset_version',v.actor_ruleset_version,
			'fingerprint',v.fingerprint,
			'scan_count',v.scan_count
		)
	FROM tokens t
	JOIN LATERAL (
		SELECT grade,verdict,ruleset_version,actor_ruleset_version,signature,fingerprint,last_seen_at,scan_count
		FROM security_unified_radar_verdicts
		WHERE network=$1
		  AND target_kind='token'
		  AND target_id=t.mint
		  AND signed=true
		  AND signature IS NOT NULL
		  AND btrim(signature)<>''
		ORDER BY last_seen_at DESC,created_at DESC,id DESC
		LIMIT 1
	) v ON true

	UNION ALL

	SELECT
		t.funded_wallet,'wallet','creator_deployer',
		t.mint,'token','creator_linked_token',
		x.event_kind,x.evidence_state,'exit_event',x.signature,x.slot,x.observed_at,
		'security_actor_exit_events',
		jsonb_build_object(
			'funding_source_wallet',t.source_wallet,
			'direct_source_of_subject',t.direct_source_of_subject,
			'source_rule_id',x.source_rule_id,
			'detail',x.detail
		)
	FROM tokens t
	JOIN security_actor_exit_events x
	  ON x.network=$1 AND x.actor_wallet=t.funded_wallet AND x.target=t.mint
)
SELECT
	source_id,source_kind,source_role,target_id,target_kind,target_role,
	relation,evidence_state,evidence_kind,signature,slot,observed_at,source_provider,metadata
FROM trajectory
WHERE btrim(source_id)<>'' AND btrim(target_id)<>''
ORDER BY observed_at ASC,source_id ASC,relation ASC,target_id ASC
LIMIT $3`
