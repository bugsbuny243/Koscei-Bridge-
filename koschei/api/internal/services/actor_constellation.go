package services

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const ActorConstellationVersion = "koschei-actor-constellation-v1"

const (
	defaultActorConstellationDepth   = 2
	defaultActorConstellationFanout  = 8
	defaultActorConstellationNodeCap = 25
	maxActorConstellationDepth       = 3
	maxActorConstellationFanout      = 20
	maxActorConstellationNodeCap     = 50
)

type ActorConstellationEvidenceRow struct {
	ID                 string    `json:"id"`
	Signature          string    `json:"signature"`
	Slot               int64     `json:"slot"`
	Timestamp          time.Time `json:"timestamp"`
	SourceWallet       string    `json:"source_wallet"`
	DestinationWallet  string    `json:"destination_wallet"`
	Amount             string    `json:"amount"`
	Asset              string    `json:"asset"`
	Program            string    `json:"program"`
	VerificationStatus string    `json:"verification_status"`
	Relation           string    `json:"relation"`
}

type ActorConstellationNode struct {
	Wallet             string   `json:"wallet"`
	Hop                int      `json:"hop"`
	ViaWallet          string   `json:"via_wallet,omitempty"`
	LinkClassification string   `json:"link_classification,omitempty"`
	EvidenceStatus     string   `json:"evidence_status,omitempty"`
	Rules              []string `json:"rules"`
}

type ActorConstellationEdge struct {
	FromWallet               string                          `json:"from_wallet"`
	ToWallet                 string                          `json:"to_wallet"`
	Classification           string                          `json:"classification"`
	EvidenceStatus           string                          `json:"evidence_status"`
	Rules                    []string                        `json:"rules"`
	DirectVerifiedRelations  int                             `json:"direct_verified_relations"`
	SharedCounterpartCount   int                             `json:"shared_counterpart_count"`
	SharedRelationCount      int                             `json:"shared_relation_count"`
	SharedFundingSourceCount int                             `json:"shared_funding_source_count"`
	VerifiedOverlapCount     int                             `json:"verified_overlap_count"`
	Evidence                 []ActorConstellationEvidenceRow `json:"evidence"`
}

type ActorConstellationReport struct {
	Version     string                   `json:"version"`
	SeedWallet  string                   `json:"seed_wallet"`
	Network     string                   `json:"network"`
	Available   bool                     `json:"available"`
	Status      string                   `json:"status"`
	Complete    bool                     `json:"complete"`
	NodeCount   int                      `json:"node_count"`
	EdgeCount   int                      `json:"edge_count"`
	MaxDepth    int                      `json:"max_depth"`
	Fanout      int                      `json:"fanout"`
	NodeCap     int                      `json:"node_cap"`
	Nodes       []ActorConstellationNode `json:"nodes"`
	Edges       []ActorConstellationEdge `json:"edges"`
	GeneratedAt time.Time                `json:"generated_at"`
	Policy      map[string]any           `json:"policy"`
	Limitations []string                 `json:"limitations"`
}

type actorConstellationLookup func(context.Context, string, string, int) (actorConstellationLookupResult, error)

type actorConstellationQueueItem struct {
	Wallet string
	Hop    int
}

func (s *ActorDefenseStore) LoadActorConstellation(ctx context.Context, wallet, network string, maxDepth, fanout, nodeCap int) (ActorConstellationReport, error) {
	if s == nil || s.DB == nil {
		return ActorConstellationReport{}, fmt.Errorf("actor defense database is unavailable")
	}
	return buildActorConstellation(ctx, wallet, network, maxDepth, fanout, nodeCap, s.loadBoundedActorConstellationCandidates)
}

func buildActorConstellation(ctx context.Context, wallet, network string, maxDepth, fanout, nodeCap int, lookup actorConstellationLookup) (ActorConstellationReport, error) {
	wallet = strings.TrimSpace(wallet)
	network = normalizeRadarNetwork(network)
	if wallet == "" {
		return ActorConstellationReport{}, fmt.Errorf("actor wallet is required")
	}
	if lookup == nil {
		return ActorConstellationReport{}, fmt.Errorf("actor operational lookup is unavailable")
	}
	maxDepth, fanout, nodeCap = normalizeActorConstellationBounds(maxDepth, fanout, nodeCap)

	out := ActorConstellationReport{
		Version:     ActorConstellationVersion,
		SeedWallet:  wallet,
		Network:     network,
		Status:      "no_constellation_observed",
		Complete:    true,
		MaxDepth:    maxDepth,
		Fanout:      fanout,
		NodeCap:     nodeCap,
		Nodes:       []ActorConstellationNode{{Wallet: wallet, Hop: 0, Rules: []string{}}},
		Edges:       []ActorConstellationEdge{},
		GeneratedAt: time.Now().UTC(),
		Policy: map[string]any{
			"real_world_identity_claim":         false,
			"same_operator_claim":               false,
			"wrongdoing_claim":                  false,
			"transitive_identity_claim":         false,
			"grade_authority":                   false,
			"verdict_authority":                 false,
			"guard_block_authority":             false,
			"weak_single_observation_expansion": false,
			"serious_edges_require_evidence":    true,
			"shortest_hop_path_preserved":       true,
			"bounded_graph":                     true,
			"ruleset":                           ActorConstellationVersion,
		},
		Limitations: []string{},
	}

	visited := map[string]int{wallet: 0}
	edges := map[string]ActorConstellationEdge{}
	queue := []actorConstellationQueueItem{{Wallet: wallet, Hop: 0}}
	truncated := false
	depthLimited := false

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.Hop >= maxDepth {
			if current.Hop > 0 {
				depthLimited = true
			}
			continue
		}

		lookupResult, err := lookup(ctx, current.Wallet, network, fanout+1)
		if err != nil {
			return ActorConstellationReport{}, fmt.Errorf("load bounded operational memory for %s: %w", current.Wallet, err)
		}
		if !lookupResult.Complete {
			truncated = true
		}
		candidates := lookupResult.Candidates
		if len(candidates) > fanout {
			truncated = true
			candidates = candidates[:fanout]
		}
		for _, candidateRow := range candidates {
			match := candidateRow.Match
			candidate := strings.TrimSpace(match.Wallet)
			if candidate == "" || candidate == current.Wallet || !actorConstellationExpansionEligible(match.Classification) {
				continue
			}
			if !actorConstellationEvidenceSupports(match.Classification, candidateRow.Evidence) {
				continue
			}

			_, seen := visited[candidate]
			if !seen && len(out.Nodes) >= nodeCap {
				truncated = true
				continue
			}

			edge := actorConstellationEdgeFromCandidate(current.Wallet, candidate, candidateRow)
			key := actorConstellationEdgeKey(edge.FromWallet, edge.ToWallet)
			if existing, ok := edges[key]; !ok || actorConstellationEdgeRank(edge) > actorConstellationEdgeRank(existing) {
				edges[key] = edge
			}
			if seen {
				continue
			}

			hop := current.Hop + 1
			visited[candidate] = hop
			out.Nodes = append(out.Nodes, ActorConstellationNode{
				Wallet:             candidate,
				Hop:                hop,
				ViaWallet:          current.Wallet,
				LinkClassification: match.Classification,
				EvidenceStatus:     match.EvidenceStatus,
				Rules:              append([]string(nil), match.Rules...),
			})
			queue = append(queue, actorConstellationQueueItem{Wallet: candidate, Hop: hop})
		}
	}

	for i := range out.Nodes {
		if out.Nodes[i].Hop == 0 || out.Nodes[i].ViaWallet == "" {
			continue
		}
		key := actorConstellationEdgeKey(out.Nodes[i].ViaWallet, out.Nodes[i].Wallet)
		if edge, ok := edges[key]; ok {
			out.Nodes[i].LinkClassification = edge.Classification
			out.Nodes[i].EvidenceStatus = edge.EvidenceStatus
			out.Nodes[i].Rules = append([]string(nil), edge.Rules...)
		}
	}

	out.Edges = make([]ActorConstellationEdge, 0, len(edges))
	for _, edge := range edges {
		out.Edges = append(out.Edges, edge)
	}
	sort.SliceStable(out.Edges, func(i, j int) bool {
		if out.Edges[i].FromWallet != out.Edges[j].FromWallet {
			return out.Edges[i].FromWallet < out.Edges[j].FromWallet
		}
		if out.Edges[i].ToWallet != out.Edges[j].ToWallet {
			return out.Edges[i].ToWallet < out.Edges[j].ToWallet
		}
		return out.Edges[i].Classification < out.Edges[j].Classification
	})
	sort.SliceStable(out.Nodes, func(i, j int) bool {
		if out.Nodes[i].Hop != out.Nodes[j].Hop {
			return out.Nodes[i].Hop < out.Nodes[j].Hop
		}
		return out.Nodes[i].Wallet < out.Nodes[j].Wallet
	})

	out.NodeCount = len(out.Nodes)
	out.EdgeCount = len(out.Edges)
	out.Available = out.EdgeCount > 0
	if out.Available {
		out.Status = "operational_constellation_observed"
	}
	if truncated || depthLimited {
		out.Complete = false
	}
	if truncated {
		out.Limitations = append(out.Limitations, "The constellation hit a configured SQL input, evidence, fanout or node bound; omitted wallets and edges may exist outside this bounded view.")
	}
	if depthLimited {
		out.Limitations = append(out.Limitations, "The graph reached the requested depth frontier. Frontier wallets were not expanded, so the bounded view is intentionally marked incomplete.")
	}
	out.Limitations = append(out.Limitations,
		"Every returned serious edge carries evidence rows with signature, slot, timestamp, source, destination, amount, program and verification status.",
		"Constellation edges summarize on-chain operational evidence between wallet addresses; they do not identify a real-world person or prove common control.",
		"Transitive graph proximity is investigation context only. A path A-B-C never upgrades A and C into the same operator or identity.",
		"Single observed counterparty links and single operational overlaps are intentionally excluded from graph expansion to reduce noisy transitive clustering.",
	)
	return out, nil
}

func normalizeActorConstellationBounds(maxDepth, fanout, nodeCap int) (int, int, int) {
	if maxDepth <= 0 || maxDepth > maxActorConstellationDepth {
		maxDepth = defaultActorConstellationDepth
	}
	if fanout <= 0 || fanout > maxActorConstellationFanout {
		fanout = defaultActorConstellationFanout
	}
	if nodeCap <= 1 || nodeCap > maxActorConstellationNodeCap {
		nodeCap = defaultActorConstellationNodeCap
	}
	return maxDepth, fanout, nodeCap
}

func actorConstellationExpansionEligible(classification string) bool {
	switch strings.TrimSpace(classification) {
	case "verified_counterparty_link", "repeated_operational_overlap", "repeated_funding_overlap":
		return true
	default:
		return false
	}
}

func actorConstellationEdgeFromCandidate(from, to string, candidate actorConstellationCandidate) ActorConstellationEdge {
	from, to = canonicalActorConstellationPair(from, to)
	match := candidate.Match
	return ActorConstellationEdge{
		FromWallet:               from,
		ToWallet:                 to,
		Classification:           strings.TrimSpace(match.Classification),
		EvidenceStatus:           strings.TrimSpace(match.EvidenceStatus),
		Rules:                    append([]string(nil), match.Rules...),
		DirectVerifiedRelations:  match.DirectVerifiedRelations,
		SharedCounterpartCount:   match.SharedCounterpartCount,
		SharedRelationCount:      match.SharedRelationCount,
		SharedFundingSourceCount: match.SharedFundingSourceCount,
		VerifiedOverlapCount:     match.VerifiedOverlapCount,
		Evidence:                 append([]ActorConstellationEvidenceRow(nil), candidate.Evidence...),
	}
}

func canonicalActorConstellationPair(a, b string) (string, string) {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a <= b {
		return a, b
	}
	return b, a
}

func actorConstellationEdgeKey(a, b string) string {
	a, b = canonicalActorConstellationPair(a, b)
	return a + "\x00" + b
}

func actorConstellationEdgeRank(edge ActorConstellationEdge) int {
	switch strings.TrimSpace(edge.Classification) {
	case "verified_counterparty_link":
		return 3_000_000 + boundedActorConstellationMetric(edge.DirectVerifiedRelations)
	case "repeated_operational_overlap":
		return 2_000_000 + boundedActorConstellationMetric(edge.VerifiedOverlapCount)
	case "repeated_funding_overlap":
		return 1_000_000 + boundedActorConstellationMetric(edge.SharedFundingSourceCount)
	default:
		return 0
	}
}

func boundedActorConstellationMetric(value int) int {
	if value < 0 {
		return 0
	}
	if value > 999_999 {
		return 999_999
	}
	return value
}
