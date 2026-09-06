package services

import (
	"sort"
	"strings"
)

type ActorResolvedEntity struct {
	ID                 string         `json:"id"`
	Kinds              []string       `json:"kinds"`
	Roles              []string       `json:"roles"`
	VerificationStatus string         `json:"verification_status"`
	RelationshipCount  int            `json:"relationship_count"`
	Metadata           map[string]any `json:"metadata"`
}

type ActorResolvedRelationship struct {
	SourceEntity       string         `json:"source_entity"`
	TargetEntity       string         `json:"target_entity"`
	Relation           string         `json:"relation"`
	VerificationStatus string         `json:"verification_status"`
	Signature          string         `json:"signature,omitempty"`
	Slot               int64          `json:"slot,omitempty"`
	SourceProvider     string         `json:"source_provider"`
	EvidenceKey        string         `json:"evidence_key,omitempty"`
	Metadata           map[string]any `json:"metadata"`
}

type ActorEntityResolution struct {
	Available           bool                        `json:"available"`
	RootEntity          string                      `json:"root_entity"`
	EntityCount         int                         `json:"entity_count"`
	RelationshipCount   int                         `json:"relationship_count"`
	VerifiedRelations   int                         `json:"verified_relations"`
	ObservedRelations   int                         `json:"observed_relations"`
	InferredRelations   int                         `json:"inferred_relations"`
	UnverifiedRelations int                         `json:"unverified_relations"`
	Entities            []ActorResolvedEntity       `json:"entities"`
	Relationships       []ActorResolvedRelationship `json:"relationships"`
	Policy              map[string]any              `json:"policy"`
}

type actorResolvedEntityBuilder struct {
	id       string
	kinds    map[string]struct{}
	roles    map[string]struct{}
	status   string
	metadata map[string]any
	count    int
}

// BuildActorEntityResolution promotes the persistent evidence graph from raw
// addresses into an entity-oriented projection without clustering identities.
// A resolved entity is only a normalized evidence subject keyed by its literal
// on-chain/provider identifier. It never means common ownership or common actor.
func BuildActorEntityResolution(dossier ActorDefenseDossier) ActorEntityResolution {
	graph := BuildActorEvidenceGraph(dossier)
	out := ActorEntityResolution{
		RootEntity:    strings.TrimSpace(dossier.Wallet),
		Entities:      []ActorResolvedEntity{},
		Relationships: []ActorResolvedRelationship{},
		Policy: map[string]any{
			"entity_is_evidence_subject_not_identity": true,
			"no_common_ownership_inference":           true,
			"no_evidence_no_relationship":             true,
			"same_identifier_can_have_multiple_kinds": true,
			"identity_or_wrongdoing_claim":            false,
		},
	}
	if out.RootEntity == "" {
		return out
	}

	builders := map[string]*actorResolvedEntityBuilder{}
	ensure := func(id string) *actorResolvedEntityBuilder {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil
		}
		key := strings.ToLower(id)
		if current := builders[key]; current != nil {
			return current
		}
		current := &actorResolvedEntityBuilder{
			id:       id,
			kinds:    map[string]struct{}{},
			roles:    map[string]struct{}{},
			status:   "unverified",
			metadata: map[string]any{},
		}
		builders[key] = current
		return current
	}

	for _, node := range graph.Nodes {
		entity := ensure(node.ID)
		if entity == nil {
			continue
		}
		if kind := strings.TrimSpace(node.Kind); kind != "" {
			entity.kinds[kind] = struct{}{}
		}
		if role := strings.TrimSpace(node.Role); role != "" {
			entity.roles[role] = struct{}{}
		}
		if actorGraphStatusRank(node.VerificationStatus) > actorGraphStatusRank(entity.status) {
			entity.status = normalizeActorGraphStatus(node.VerificationStatus)
		}
		for key, value := range node.Metadata {
			if _, exists := entity.metadata[key]; !exists {
				entity.metadata[key] = value
			}
		}
	}

	for _, edge := range graph.Edges {
		source := ensure(edge.Source)
		target := ensure(edge.Target)
		if source == nil || target == nil {
			continue
		}
		source.count++
		target.count++
		evidenceKey := strings.TrimSpace(actorGraphMetadataString(edge.Metadata, "evidence_key"))
		out.Relationships = append(out.Relationships, ActorResolvedRelationship{
			SourceEntity:       edge.Source,
			TargetEntity:       edge.Target,
			Relation:           edge.Relation,
			VerificationStatus: edge.VerificationStatus,
			Signature:          edge.Signature,
			Slot:               edge.Slot,
			SourceProvider:     edge.SourceProvider,
			EvidenceKey:        evidenceKey,
			Metadata:           cloneActorGraphMetadata(edge.Metadata),
		})
		switch normalizeActorGraphStatus(edge.VerificationStatus) {
		case "verified":
			out.VerifiedRelations++
		case "observed":
			out.ObservedRelations++
		case "inferred":
			out.InferredRelations++
		default:
			out.UnverifiedRelations++
		}
	}

	for _, builder := range builders {
		entity := ActorResolvedEntity{
			ID:                 builder.id,
			Kinds:              actorEntitySortedKeys(builder.kinds),
			Roles:              actorEntitySortedKeys(builder.roles),
			VerificationStatus: normalizeActorGraphStatus(builder.status),
			RelationshipCount:  builder.count,
			Metadata:           nonNilMap(builder.metadata),
		}
		out.Entities = append(out.Entities, entity)
	}
	sort.SliceStable(out.Entities, func(i, j int) bool {
		return out.Entities[i].ID < out.Entities[j].ID
	})
	sort.SliceStable(out.Relationships, func(i, j int) bool {
		left, right := out.Relationships[i], out.Relationships[j]
		if left.SourceEntity != right.SourceEntity {
			return left.SourceEntity < right.SourceEntity
		}
		if left.TargetEntity != right.TargetEntity {
			return left.TargetEntity < right.TargetEntity
		}
		if left.Relation != right.Relation {
			return left.Relation < right.Relation
		}
		return left.EvidenceKey < right.EvidenceKey
	})
	out.EntityCount = len(out.Entities)
	out.RelationshipCount = len(out.Relationships)
	out.Available = out.RelationshipCount > 0
	return out
}

func actorEntitySortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
