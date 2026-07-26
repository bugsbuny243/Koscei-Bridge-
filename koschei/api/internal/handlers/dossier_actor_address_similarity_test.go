package handlers

import "testing"

func TestActorDossierAddressSimilarityClustersFindsReferencePatterns(t *testing.T) {
	actor := "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe"
	evidence := []any{
		map[string]any{"actor_wallet": actor, "counterpart_kind": "wallet", "counterpart_id": "4qcD8iSFLC5VDZphBtM7pSeevtHtD8Chi7Zmhcm9TvHm", "signature": "sig-1"},
		map[string]any{"actor_wallet": actor, "counterpart_kind": "wallet", "counterpart_id": "4qcD6f4EWDD4TiZj72BAn9jeXrU6tvBWkRAhPdpeTvHm", "signature": "sig-2"},
		map[string]any{"actor_wallet": actor, "counterpart_kind": "wallet", "counterpart_id": "4qcDiTnQvXRQirV2DxYjomS6N1h8LFCeP3JqtqXq4vHm", "signature": "sig-3"},
		map[string]any{"actor_wallet": actor, "counterpart_kind": "wallet", "counterpart_id": "EH11K49QnGLi2jNRzMRYCHHAbw7JV4Ma76DsPws1YJ1K", "signature": "sig-4"},
		map[string]any{"actor_wallet": actor, "counterpart_kind": "wallet", "counterpart_id": "EH1oGNizBQxMDddGuLWj6SxpKts338H891Gh4kqbrJ1K", "signature": "sig-5"},
	}
	clusters := actorDossierAddressSimilarityClusters(evidence)
	byPattern := map[string]map[string]any{}
	for _, raw := range clusters {
		cluster := dossierMap(raw)
		byPattern[dossierString(cluster["pattern"])] = cluster
	}
	prefix := byPattern["4qcD*"]
	if len(prefix) == 0 || publicDossierInt(prefix["address_count"]) != 3 {
		t.Fatalf("4qcD cluster=%#v all=%#v", prefix, clusters)
	}
	vanity := byPattern["EH1*…J1K"]
	if len(vanity) == 0 || publicDossierInt(vanity["address_count"]) != 2 {
		t.Fatalf("EH1/J1K cluster=%#v all=%#v", vanity, clusters)
	}
	for _, cluster := range []map[string]any{prefix, vanity} {
		if dossierString(cluster["verification_status"]) != "inferred" || dossierString(cluster["grade_effect"]) != "none" {
			t.Fatalf("cluster escaped watch-only boundary: %#v", cluster)
		}
		if !containsDossierText(dossierString(cluster["limitation"]), "does not prove") {
			t.Fatalf("identity/common-control limitation missing: %#v", cluster)
		}
	}
	if _, duplicated := byPattern["4qc*…vHm"]; duplicated {
		t.Fatalf("prefix cluster was duplicated by a weaker prefix/suffix cluster: %#v", clusters)
	}
}

func TestActorDossierAddressSimilarityClustersExcludesTargetWallet(t *testing.T) {
	actor := "4qcD8iSFLC5VDZphBtM7pSeevtHtD8Chi7Zmhcm9TvHm"
	evidence := []any{
		map[string]any{"actor_wallet": actor, "counterpart_kind": "wallet", "counterpart_id": "4qcD6f4EWDD4TiZj72BAn9jeXrU6tvBWkRAhPdpeTvHm", "signature": "sig-1"},
		map[string]any{"actor_wallet": actor, "counterpart_kind": "wallet", "counterpart_id": "4qcDiTnQvXRQirV2DxYjomS6N1h8LFCeP3JqtqXq4vHm", "signature": "sig-2"},
	}
	clusters := actorDossierAddressSimilarityClusters(evidence)
	for _, raw := range clusters {
		for _, member := range publicCaseStrings(dossierMap(raw)["addresses"]) {
			if member == actor {
				t.Fatalf("target actor leaked into candidate cluster: %#v", clusters)
			}
		}
	}
}

func containsDossierText(value, fragment string) bool {
	return len(value) >= len(fragment) && (value == fragment || findDossierFragment(value, fragment))
}

func findDossierFragment(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
