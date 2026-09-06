package services

import (
	"sort"
	"strings"
	"time"
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
	ObservedAt         time.Time      `json:"observed_at"`
	TokenMint          string         `json:"token_mint,omitempty"`
	TokenAmount        float64        `json:"token_amount,omitempty"`
	NativeAmount       float64        `json:"native_amount,omitempty"`
	SourceProvider     string         `json:"source_provider"`
	EvidenceKey        string         `json:"evidence_key,omitempty"`
	Metadata           map[string]any `json:"metadata"`
}

type ActorResolvedTransaction struct {
	Signature          string    `json:"signature"`
	Slot               int64     `json:"slot,omitempty"`
	Slots              []int64   `json:"slots,omitempty"`
	SlotConflict       bool      `json:"slot_conflict"`
	ObservedAt         time.Time `json:"observed_at"`
	VerificationStatus string    `json:"verification_status"`
	EvidenceStatuses   []string  `json:"evidence_statuses"`
	EntityIDs          []string  `json:"entity_ids"`
	Relations          []string  `json:"relations"`
	SourceProviders    []string  `json:"source_providers"`
	EvidenceKeys       []string  `json:"evidence_keys"`
}

type ActorEntityResolution struct {
	Available           bool                        `json:"available"`
	RootEntity          string                      `json:"root_entity"`
	EntityCount         int                         `json:"entity_count"`
	RelationshipCount   int                         `json:"relationship_count"`
	TransactionCount    int                         `json:"transaction_count"`
	VerifiedRelations   int                         `json:"verified_relations"`
	ObservedRelations   int                         `json:"observed_relations"`
	InferredRelations   int                         `json:"inferred_relations"`
	UnverifiedRelations int                         `json:"unverified_relations"`
	Entities            []ActorResolvedEntity       `json:"entities"`
	Relationships       []ActorResolvedRelationship `json:"relationships"`
	Transactions        []ActorResolvedTransaction  `json:"transactions"`
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

type actorResolvedTransactionBuilder struct {
	signature string
	observed  time.Time
	status    string
	slots     map[int64]struct{}
	statuses  map[string]struct{}
	entities  map[string]struct{}
	relations map[string]struct{}
	providers map[string]struct{}
	evidence  map[string]struct{}
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
		Transactions:  []ActorResolvedTransaction{},
		Policy: map[string]any{
			"entity_is_evidence_subject_not_identity":           true,
			"no_common_ownership_inference":                     true,
			"no_evidence_no_relationship":                       true,
			"same_identifier_can_have_multiple_kinds":           true,
			"identifiers_are_case_sensitive":                    true,
			"transaction_projection_requires_signature":         true,
			"unsigned_relationship_not_promoted_to_transaction": true,
			"transaction_slot_conflicts_are_explicit":           true,
			"mixed_evidence_statuses_are_preserved":             true,
			"identity_or_wrongdoing_claim":                      false,
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
		if current := builders[id]; current != nil {
			return current
		}
		current := &actorResolvedEntityBuilder{
			id:       id,
			kinds:    map[string]struct{}{},
			roles:    map[string]struct{}{},
			status:   "unverified",
			metadata: map[string]any{},
		}
		builders[id] = current
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

	transactionBuilders := map[string]*actorResolvedTransactionBuilder{}
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
			ObservedAt:         edge.ObservedAt,
			TokenMint:          edge.TokenMint,
			TokenAmount:        edge.TokenAmount,
			NativeAmount:       edge.NativeAmount,
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

		signature := strings.TrimSpace(edge.Signature)
		if signature == "" {
			continue
		}
		transaction := transactionBuilders[signature]
		if transaction == nil {
			transaction = &actorResolvedTransactionBuilder{
				signature: signature,
				status:    "unverified",
				slots:     map[int64]struct{}{},
				statuses:  map[string]struct{}{},
				entities:  map[string]struct{}{},
				relations: map[string]struct{}{},
				providers: map[string]struct{}{},
				evidence:  map[string]struct{}{},
			}
			transactionBuilders[signature] = transaction
		}
		if edge.Slot != 0 {
			transaction.slots[edge.Slot] = struct{}{}
		}
		if transaction.observed.IsZero() || (!edge.ObservedAt.IsZero() && edge.ObservedAt.Before(transaction.observed)) {
			transaction.observed = edge.ObservedAt
		}
		normalizedStatus := normalizeActorGraphStatus(edge.VerificationStatus)
		transaction.statuses[normalizedStatus] = struct{}{}
		if actorGraphStatusRank(normalizedStatus) > actorGraphStatusRank(transaction.status) {
			transaction.status = normalizedStatus
		}
		transaction.entities[edge.Source] = struct{}{}
		transaction.entities[edge.Target] = struct{}{}
		if relation := strings.TrimSpace(edge.Relation); relation != "" {
			transaction.relations[relation] = struct{}{}
		}
		if provider := strings.TrimSpace(edge.SourceProvider); provider != "" {
			transaction.providers[provider] = struct{}{}
		}
		if evidenceKey != "" {
			transaction.evidence[evidenceKey] = struct{}{}
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
	for _, builder := range transactionBuilders {
		slots := actorEntitySortedInt64Keys(builder.slots)
		slot := int64(0)
		if len(slots) == 1 {
			slot = slots[0]
		}
		out.Transactions = append(out.Transactions, ActorResolvedTransaction{
			Signature:          builder.signature,
			Slot:               slot,
			Slots:              slots,
			SlotConflict:       len(slots) > 1,
			ObservedAt:         builder.observed,
			VerificationStatus: normalizeActorGraphStatus(builder.status),
			EvidenceStatuses:   actorEntitySortedKeys(builder.statuses),
			EntityIDs:          actorEntitySortedKeys(builder.entities),
			Relations:          actorEntitySortedKeys(builder.relations),
			SourceProviders:    actorEntitySortedKeys(builder.providers),
			EvidenceKeys:       actorEntitySortedKeys(builder.evidence),
		})
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
	sort.SliceStable(out.Transactions, func(i, j int) bool {
		left, right := out.Transactions[i], out.Transactions[j]
		if left.ObservedAt.Equal(right.ObservedAt) {
			return left.Signature < right.Signature
		}
		if left.ObservedAt.IsZero() {
			return false
		}
		if right.ObservedAt.IsZero() {
			return true
		}
		return left.ObservedAt.Before(right.ObservedAt)
	})
	out.EntityCount = len(out.Entities)
	out.RelationshipCount = len(out.Relationships)
	out.TransactionCount = len(out.Transactions)
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

func actorEntitySortedInt64Keys(values map[int64]struct{}) []int64 {
	out := make([]int64, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
