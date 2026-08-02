package services

import (
	"sort"
	"strings"
	"time"
)

type ActorEvidenceGraphNode struct {
	ID                 string         `json:"id"`
	Kind               string         `json:"kind"`
	Role               string         `json:"role"`
	VerificationStatus string         `json:"verification_status"`
	Metadata           map[string]any `json:"metadata"`
}

type ActorEvidenceGraphEdge struct {
	Source             string         `json:"source"`
	Target             string         `json:"target"`
	Relation           string         `json:"relation"`
	VerificationStatus string         `json:"verification_status"`
	Signature          string         `json:"signature,omitempty"`
	Slot               int64          `json:"slot,omitempty"`
	ObservedAt         time.Time      `json:"observed_at"`
	TokenMint          string         `json:"token_mint,omitempty"`
	TokenAmount        float64        `json:"token_amount,omitempty"`
	NativeAmount       float64        `json:"native_amount,omitempty"`
	SourceProvider     string         `json:"source_provider"`
	Metadata           map[string]any `json:"metadata"`
}

type ActorEvidenceGraph struct {
	Available       bool                     `json:"available"`
	ActorWallet     string                   `json:"actor_wallet"`
	NodeCount       int                      `json:"node_count"`
	EdgeCount       int                      `json:"edge_count"`
	VerifiedEdges   int                      `json:"verified_edges"`
	ObservedEdges   int                      `json:"observed_edges"`
	InferredEdges   int                      `json:"inferred_edges"`
	UnverifiedEdges int                      `json:"unverified_edges"`
	Nodes           []ActorEvidenceGraphNode `json:"nodes"`
	Edges           []ActorEvidenceGraphEdge `json:"edges"`
	Policy          map[string]any           `json:"policy"`
}

// BuildActorEvidenceGraph is a pure projection over persistent evidence. It does
// not infer ownership, identity or intent. Edges are created only from explicit
// ActorDefenseEvidenceRecord rows; dossier inventory can add nodes but never an
// unsupported relation edge.
func BuildActorEvidenceGraph(dossier ActorDefenseDossier) ActorEvidenceGraph {
	actor := strings.TrimSpace(dossier.Wallet)
	out := ActorEvidenceGraph{
		ActorWallet: actor, Nodes: []ActorEvidenceGraphNode{}, Edges: []ActorEvidenceGraphEdge{},
		Policy: map[string]any{
			"no_evidence_no_edge":                   true,
			"inventory_does_not_create_edges":       true,
			"external_attribution_is_observed_only": true,
			"identity_or_wrongdoing_claim":          false,
		},
	}
	if actor == "" {
		return out
	}
	nodes := map[string]ActorEvidenceGraphNode{}
	edges := map[string]ActorEvidenceGraphEdge{}
	upsertNode := func(id, kind, role, status string, metadata map[string]any) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		if kind == "" {
			kind = "wallet"
		}
		key := strings.ToLower(kind + "|" + id)
		candidate := ActorEvidenceGraphNode{ID: id, Kind: kind, Role: role, VerificationStatus: normalizeActorGraphStatus(status), Metadata: nonNilMap(metadata)}
		current, exists := nodes[key]
		if !exists || actorGraphStatusRank(candidate.VerificationStatus) > actorGraphStatusRank(current.VerificationStatus) {
			nodes[key] = candidate
		}
	}
	upsertNode(actor, "wallet", "investigated_actor", "verified", map[string]any{"root": true})
	for _, token := range dossier.Tokens {
		status := "observed"
		if strings.TrimSpace(token.CreatorSignature) == "" {
			status = "unverified"
		}
		upsertNode(token.Mint, "token", actorGraphTokenRole(token.Roles), status, map[string]any{
			"roles":             token.Roles,
			"creator_signature": token.CreatorSignature,
			"holder_rank":       token.HolderRank,
			"holder_percentage": token.HolderPercentage,
			"first_observed_at": token.FirstObservedAt,
			"last_observed_at":  token.LastObservedAt,
		})
	}
	for _, related := range dossier.RelatedActors {
		upsertNode(related.Wallet, "wallet", "repeat_related_actor", "observed", map[string]any{
			"shared_token_count":    related.SharedTokenCount,
			"max_holder_percentage": related.MaxPercentage,
			"first_observed_at":     related.FirstObservedAt,
			"last_observed_at":      related.LastObservedAt,
		})
	}

	for _, evidence := range dossier.Evidence {
		counterpart := strings.TrimSpace(evidence.CounterpartID)
		if counterpart == "" {
			continue
		}
		kind := actorGraphNodeKind(evidence.CounterpartKind)
		role := actorGraphCounterpartRole(evidence)
		upsertNode(counterpart, kind, role, evidence.VerificationStatus, map[string]any{
			"token_mint":      evidence.TokenMint,
			"source_provider": evidence.Source,
		})
		sourceID := actor
		targetID := counterpart
		if actorGraphRelationPointsToActor(evidence.Relation) {
			sourceID, targetID = counterpart, actor
		}
		metadata := cloneActorGraphMetadata(evidence.Metadata)
		metadata["evidence_key"] = evidence.EvidenceKey
		metadata["occurrence_count"] = evidence.OccurrenceCount
		edge := ActorEvidenceGraphEdge{
			Source: sourceID, Target: targetID, Relation: strings.TrimSpace(evidence.Relation),
			VerificationStatus: normalizeActorGraphStatus(evidence.VerificationStatus),
			Signature:          strings.TrimSpace(evidence.Signature), Slot: evidence.Slot,
			ObservedAt: evidence.ObservedAt, TokenMint: strings.TrimSpace(evidence.TokenMint),
			TokenAmount: evidence.TokenAmount, NativeAmount: evidence.AmountNative,
			SourceProvider: strings.TrimSpace(evidence.Source), Metadata: metadata,
		}
		key := strings.ToLower(edge.Source + "|" + edge.Target + "|" + edge.Relation + "|" + edge.Signature + "|" + evidence.EvidenceKey)
		if _, exists := edges[key]; !exists {
			edges[key] = edge
		}
	}

	for _, node := range nodes {
		out.Nodes = append(out.Nodes, node)
	}
	for _, edge := range edges {
		out.Edges = append(out.Edges, edge)
		switch edge.VerificationStatus {
		case "verified":
			out.VerifiedEdges++
		case "observed":
			out.ObservedEdges++
		case "inferred":
			out.InferredEdges++
		default:
			out.UnverifiedEdges++
		}
	}
	sort.SliceStable(out.Nodes, func(i, j int) bool {
		if out.Nodes[i].Kind != out.Nodes[j].Kind {
			return out.Nodes[i].Kind < out.Nodes[j].Kind
		}
		return out.Nodes[i].ID < out.Nodes[j].ID
	})
	sort.SliceStable(out.Edges, func(i, j int) bool {
		if out.Edges[i].ObservedAt.Equal(out.Edges[j].ObservedAt) {
			if out.Edges[i].Relation != out.Edges[j].Relation {
				return out.Edges[i].Relation < out.Edges[j].Relation
			}
			return out.Edges[i].Target < out.Edges[j].Target
		}
		return out.Edges[i].ObservedAt.Before(out.Edges[j].ObservedAt)
	})
	out.NodeCount = len(out.Nodes)
	out.EdgeCount = len(out.Edges)
	out.Available = out.EdgeCount > 0
	return out
}

func actorGraphTokenRole(roles []string) string {
	for _, preferred := range []string{"creator_deployer", "dominant_holder", "trader"} {
		for _, role := range roles {
			if strings.EqualFold(strings.TrimSpace(role), preferred) {
				return preferred
			}
		}
	}
	return "related_token"
}

func actorGraphNodeKind(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "token", "mint":
		return "token"
	case "pool", "liquidity_pool":
		return "pool"
	case "transaction", "signature":
		return "transaction"
	case "program":
		return "program"
	case "external_attribution", "service", "exchange":
		return "service"
	default:
		return "wallet"
	}
}

func actorGraphCounterpartRole(evidence ActorDefenseEvidenceRecord) string {
	if value := strings.TrimSpace(actorGraphMetadataString(evidence.Metadata, "counterpart_role")); value != "" {
		return value
	}
	switch strings.ToLower(strings.TrimSpace(evidence.Relation)) {
	case "created_token":
		return "created_token"
	case "funded_by", "external_funding_attribution":
		return "actor_funder"
	case "initial_token_recipient", "creator_recipient_in_window":
		return "token_recipient"
	case "liquidity_remove_activity":
		return "liquidity_pool_or_transaction"
	case "external_account_attribution":
		return "external_attribution"
	default:
		return "related_actor"
	}
}

func actorGraphRelationPointsToActor(relation string) bool {
	switch strings.ToLower(strings.TrimSpace(relation)) {
	case "funded_by", "external_funding_attribution", "funded_creator", "funding_origin":
		return true
	default:
		return false
	}
}

func normalizeActorGraphStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "verified":
		return "verified"
	case "observed":
		return "observed"
	case "inferred":
		return "inferred"
	default:
		return "unverified"
	}
}

func actorGraphStatusRank(value string) int {
	switch normalizeActorGraphStatus(value) {
	case "verified":
		return 4
	case "observed":
		return 3
	case "inferred":
		return 2
	default:
		return 1
	}
}

func cloneActorGraphMetadata(value map[string]any) map[string]any {
	out := map[string]any{}
	for key, item := range value {
		out[key] = item
	}
	return out
}

func actorGraphMetadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}
