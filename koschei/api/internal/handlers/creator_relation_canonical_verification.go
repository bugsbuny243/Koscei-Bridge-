package handlers

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"
)

type canonicalCreatorRelationVerification struct {
	Verified         bool
	Status           string
	Signature        string
	Slot             int64
	ObservedAt       time.Time
	CreatorSigner    bool
	MintReferenced   bool
	LaunchLike       bool
	InstructionTypes []string
	Limitations      []string
}

// verifyCanonicalCreatorRelation upgrades an externally discovered creator
// relation only when the exact create-transaction can be re-read through
// Koschei's canonical Solana transport and proves three independent facts:
// creator is a signer, the requested mint is structurally referenced, and the
// parsed transaction carries launch/create semantics. Discovery providers can
// suggest the signature, but cannot set Verified themselves.
func (h *Handler) verifyCanonicalCreatorRelation(ctx context.Context, target, network, creator, signature string) canonicalCreatorRelationVerification {
	out := canonicalCreatorRelationVerification{
		Status: "not_verified", Signature: strings.TrimSpace(signature),
		InstructionTypes: []string{}, Limitations: []string{},
	}
	target = strings.TrimSpace(target)
	creator = strings.TrimSpace(creator)
	network = strings.TrimSpace(network)
	if network == "" {
		network = "solana-mainnet"
	}
	if target == "" || creator == "" || out.Signature == "" {
		out.Status = "verification_inputs_incomplete"
		out.Limitations = append(out.Limitations, "Mint, creator wallet and create-transaction signature are required for canonical verification.")
		return out
	}
	if ctx == nil {
		ctx = context.Background()
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 12 * time.Second}
	rpcURL := solanaRPCURL(network, os.Getenv("ALCHEMY_API_KEY"))
	var tx map[string]any
	if err := h.callSolanaRPC(verifyCtx, client, rpcURL, network, "getTransaction", []any{
		out.Signature,
		map[string]any{"encoding": "jsonParsed", "commitment": "confirmed", "maxSupportedTransactionVersion": 0},
	}, &tx); err != nil {
		out.Status = "canonical_transaction_unavailable"
		out.Limitations = append(out.Limitations, compactRadarDetailError(err))
		return out
	}
	if len(tx) == 0 {
		out.Status = "canonical_transaction_missing"
		return out
	}

	out.Slot = creatorIntelInt64(tx["slot"])
	blockTime := creatorIntelInt64(tx["blockTime"])
	if blockTime > 0 {
		out.ObservedAt = time.Unix(blockTime, 0).UTC()
	}
	meta := creatorIntelMap(tx["meta"])
	message := creatorIntelMap(creatorIntelMap(tx["transaction"])["message"])
	accountKeys, signers := creatorIntelAccountKeys(message)
	instructionTypes, instructionMints := creatorIntelInstructions(message, meta)
	out.InstructionTypes = append([]string{}, instructionTypes...)
	out.CreatorSigner = creatorIntelContains(signers, creator)
	out.MintReferenced = creatorIntelContains(accountKeys, target) || creatorIntelContains(instructionMints, target) || canonicalTokenBalancesMentionMint(meta, target)
	logs := strings.ToLower(strings.Join(creatorIntelStringSlice(meta["logMessages"]), "\n"))
	out.LaunchLike = creatorIntelLaunchRelated(logs, instructionTypes)

	switch {
	case out.Slot <= 0:
		out.Status = "slot_unavailable"
		out.Limitations = append(out.Limitations, "Canonical transaction did not expose a positive slot.")
	case !out.CreatorSigner:
		out.Status = "creator_not_signer"
		out.Limitations = append(out.Limitations, "Discovered creator wallet was not a signer of the candidate create transaction.")
	case !out.MintReferenced:
		out.Status = "mint_not_referenced"
		out.Limitations = append(out.Limitations, "Candidate transaction did not structurally reference the requested mint.")
	case !out.LaunchLike:
		out.Status = "launch_semantics_not_verified"
		out.Limitations = append(out.Limitations, "Candidate transaction lacked parsed launch/create semantics; creator relation remains observed only.")
	default:
		out.Verified = true
		out.Status = "verified_canonical_create_transaction"
	}
	return out
}

func canonicalTokenBalancesMentionMint(meta map[string]any, mint string) bool {
	mint = strings.TrimSpace(mint)
	if mint == "" {
		return false
	}
	for _, key := range []string{"preTokenBalances", "postTokenBalances"} {
		items, _ := meta[key].([]any)
		for _, raw := range items {
			item := creatorIntelMap(raw)
			if strings.TrimSpace(creatorIntelCleanString(item["mint"])) == mint {
				return true
			}
		}
	}
	return false
}

func applyCanonicalCreatorVerification(source map[string]any, verification canonicalCreatorRelationVerification) map[string]any {
	out := cloneCreatorSourceContext(source)
	out["canonical_creator_verification"] = map[string]any{
		"verified":          verification.Verified,
		"status":            verification.Status,
		"signature":         verification.Signature,
		"slot":              verification.Slot,
		"creator_signer":    verification.CreatorSigner,
		"mint_referenced":   verification.MintReferenced,
		"launch_like":       verification.LaunchLike,
		"instruction_types": append([]string{}, verification.InstructionTypes...),
		"limitations":       append([]string{}, verification.Limitations...),
	}
	if !verification.Verified {
		return out
	}
	out["creator_relation_verified"] = true
	out["creator_relation_observed"] = true
	out["creator_resolution_status"] = "verified_canonical_rpc"
	out["creator_scope"] = "Canonical Solana create-transaction signer + mint reference + launch semantics verified; wallet relation only, not a real-world identity or wrongdoing claim."
	out["signature"] = verification.Signature
	out["creation_signature"] = verification.Signature
	out["launch_signature"] = verification.Signature
	out["slot"] = verification.Slot
	out["source"] = "solana_rpc_create_transaction"
	if !verification.ObservedAt.IsZero() {
		out["observed_at"] = verification.ObservedAt.UTC().Format(time.RFC3339)
		out["created_time"] = verification.ObservedAt.Unix()
	}
	return out
}
