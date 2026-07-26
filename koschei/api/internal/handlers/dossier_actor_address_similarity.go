package handlers

import (
	"sort"
	"strings"
)

const actorDossierAddressSimilarityVersion = "deterministic-address-similarity-v1"

// actorDossierAddressSimilarityClusters publishes deterministic Base58 visual
// similarity candidates from the immutable evidence log. These clusters are
// INFERRED/watch-only and never prove identity, intent or common control.
func actorDossierAddressSimilarityClusters(raw any) []any {
	rows := dossierSlice(raw)
	targets := map[string]bool{}
	addressSignatures := map[string]map[string]bool{}

	for _, rawRow := range rows {
		row := dossierMap(rawRow)
		if actor := strings.TrimSpace(dossierString(row["actor_wallet"])); actorDossierSolanaAddress(actor) {
			targets[actor] = true
		}
	}

	add := func(address, signature string) {
		address = strings.TrimSpace(address)
		if !actorDossierSolanaAddress(address) || targets[address] {
			return
		}
		if addressSignatures[address] == nil {
			addressSignatures[address] = map[string]bool{}
		}
		if signature = strings.TrimSpace(signature); signature != "" {
			addressSignatures[address][signature] = true
		}
	}
	for _, rawRow := range rows {
		row := dossierMap(rawRow)
		signature := dossierString(row["signature"])
		add(dossierString(row["source_wallet"]), signature)
		add(dossierString(row["destination_wallet"]), signature)
		kind := strings.ToLower(strings.TrimSpace(dossierString(row["counterpart_kind"])))
		if kind == "" || kind == "wallet" || kind == "owner_wallet" {
			add(dossierString(row["counterpart_id"]), signature)
		}
	}

	addresses := make([]string, 0, len(addressSignatures))
	for address := range addressSignatures {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)

	prefix4 := map[string][]string{}
	prefix3Suffix3 := map[string][]string{}
	for _, address := range addresses {
		prefix4[address[:4]+"*"] = append(prefix4[address[:4]+"*"], address)
		pattern := address[:3] + "*…" + address[len(address)-3:]
		prefix3Suffix3[pattern] = append(prefix3Suffix3[pattern], address)
	}

	clusters := []map[string]any{}
	prefix4Membership := map[string]string{}
	for _, pattern := range actorDossierSortedClusterPatterns(prefix4) {
		members := actorDossierUniqueSortedStrings(prefix4[pattern])
		if len(members) < 2 {
			continue
		}
		for _, address := range members {
			prefix4Membership[address] = pattern
		}
		clusters = append(clusters, actorDossierAddressCluster(pattern, "shared_prefix_4", members, addressSignatures))
	}
	for _, pattern := range actorDossierSortedClusterPatterns(prefix3Suffix3) {
		members := actorDossierUniqueSortedStrings(prefix3Suffix3[pattern])
		if len(members) < 2 || actorDossierCoveredByOnePrefixCluster(members, prefix4Membership) {
			continue
		}
		clusters = append(clusters, actorDossierAddressCluster(pattern, "shared_prefix_3_suffix_3", members, addressSignatures))
	}

	sort.SliceStable(clusters, func(i, j int) bool {
		left, right := dossierString(clusters[i]["pattern"]), dossierString(clusters[j]["pattern"])
		if left != right {
			return left < right
		}
		return dossierString(clusters[i]["match_type"]) < dossierString(clusters[j]["match_type"])
	})
	if len(clusters) > 24 {
		clusters = clusters[:24]
	}
	out := make([]any, 0, len(clusters))
	for _, cluster := range clusters {
		out = append(out, cluster)
	}
	return out
}

func actorDossierAddressCluster(pattern, matchType string, members []string, addressSignatures map[string]map[string]bool) map[string]any {
	signatures := map[string]bool{}
	for _, address := range members {
		for signature := range addressSignatures[address] {
			signatures[signature] = true
		}
	}
	return map[string]any{
		"label": "vanity_address_similarity_candidate",
		"pattern": pattern,
		"match_type": matchType,
		"addresses": members,
		"address_count": len(members),
		"distinct_signature_count": len(signatures),
		"verification_status": "inferred",
		"grade_effect": "none",
		"detector_version": actorDossierAddressSimilarityVersion,
		"limitation": "Base58 visual similarity only. This does not prove shared identity, ownership, intent or common control.",
	}
}

func actorDossierCoveredByOnePrefixCluster(members []string, membership map[string]string) bool {
	owner := ""
	for _, address := range members {
		candidate := membership[address]
		if candidate == "" {
			return false
		}
		if owner == "" {
			owner = candidate
			continue
		}
		if owner != candidate {
			return false
		}
	}
	return owner != ""
}

func actorDossierSortedClusterPatterns(groups map[string][]string) []string {
	patterns := make([]string, 0, len(groups))
	for pattern := range groups {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	return patterns
}

func actorDossierUniqueSortedStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func actorDossierSolanaAddress(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 32 || len(value) > 44 {
		return false
	}
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	for _, char := range value {
		if !strings.ContainsRune(alphabet, char) {
			return false
		}
	}
	return true
}
