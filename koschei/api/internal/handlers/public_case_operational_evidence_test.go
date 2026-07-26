package handlers

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestPublicCaseOperationalEvidenceRetainsDustWithGradeExclusionLabel(t *testing.T) {
	raw := []any{
		map[string]any{
			"relation": "direct_sol_transfer_in",
			"verification_status": "observed",
			"actor_wallet": "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe",
			"counterpart_id": "4qcD6f4EWDD4TiZj72BAn9jeXrU6tvBWkRAhPdpeTvHm",
			"source_wallet": "4qcD6f4EWDD4TiZj72BAn9jeXrU6tvBWkRAhPdpeTvHm",
			"destination_wallet": "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe",
			"signature": "dust-signature",
			"slot": 435027938,
			"observed_at": "2026-07-25T00:56:26Z",
			"amount": map[string]any{"native_sol": 0.00001},
			"program": "system",
			"possible_dust": true,
			"address_poisoning_candidate": true,
			"grade_eligible": false,
		},
	}
	rows := publicCaseOperationalEvidenceRows(raw, 5)
	if len(rows) != 1 {
		t.Fatalf("dust evidence was removed: %#v", rows)
	}
	row := rows[0]
	if row.Amount != "0.00001 SOL" {
		t.Fatalf("amount=%q", row.Amount)
	}
	for _, marker := range []string{"POSSIBLE DUST", "ADDRESS POISONING CANDIDATE", "GRADE DIŞI"} {
		if !strings.Contains(row.Classification, marker) {
			t.Fatalf("classification %q missing %q", row.Classification, marker)
		}
	}
	if row.ClassificationClass != "dust" {
		t.Fatalf("classification class=%q", row.ClassificationClass)
	}
}

func TestPublicCaseOperationalVanityClustersRemainInferred(t *testing.T) {
	raw := map[string]any{
		"address_similarity_clusters": []any{
			map[string]any{
				"pattern": "4qcD*",
				"match_type": "shared_prefix_4",
				"addresses": []any{
					"4qcD8iSFLC5VDZphBtM7pSeevtHtD8Chi7Zmhcm9TvHm",
					"4qcD6f4EWDD4TiZj72BAn9jeXrU6tvBWkRAhPdpeTvHm",
				},
				"address_count": 2,
				"distinct_signature_count": 7,
				"verification_status": "inferred",
				"grade_effect": "none",
				"limitation": "Base58 visual similarity only. This does not prove shared identity, ownership, intent or common control.",
			},
		},
	}
	clusters := publicCaseOperationalVanityClusters(raw)
	if len(clusters) != 1 {
		t.Fatalf("clusters=%#v", clusters)
	}
	cluster := clusters[0]
	if cluster.Pattern != "4qcD*" || cluster.State != "ÇIKARIM" || cluster.Class != "inferred" {
		t.Fatalf("cluster escaped inferred boundary: %#v", cluster)
	}
	if cluster.AddressCount != 2 || cluster.SignatureCount != 7 || len(cluster.Addresses) != 2 {
		t.Fatalf("cluster counts=%#v", cluster)
	}
}

func TestPublicCaseOperationalTemplateKeepsVanityClustersCollapsedWithShowAll(t *testing.T) {
	data := publicCaseOperationalPageData{
		Case: publicCasePageData{
			CaseRef: "KD1-vanitycase00000000000000000000", Title: "ARVIS Case",
			TargetKind: "wallet", TargetID: "wallet-address", TechnicalURL: "/dossier/ref",
			Acceptance: publicCaseAcceptanceView{Pass: 4, Fail: 3, NotInvestigated: 3},
			BundleHash: "sha256:bundle", RulesetVersion: "koschei-actor-defense-rules-v1.0.1",
			ProducedAt: time.Date(2026, 7, 25, 19, 0, 0, 0, time.UTC),
		},
		OutcomeLabel: "SONUÇ BEKLETİLİYOR", OutcomeClass: "review",
		OutcomeText: "Açık işler Koschei worker görevleridir.", GradeDisplay: "WITHHOLD",
		GradeExplanation: "Açık otomatik işler varken işlem onayı verilmez.",
		RuleReasons: []string{"Kanıt destekli kural yok."},
		VanityClusters: []publicCaseVanityCluster{{
			Pattern: "EH1*…J1K", MatchType: "Shared Prefix 3 Suffix 3", State: "ÇIKARIM", Class: "inferred",
			Addresses: []string{
				"EH11K49QnGLi2jNRzMRYCHHAbw7JV4Ma76DsPws1YJ1K",
				"EH1oGNizBQxMDddGuLWj6SxpKts338H891Gh4kqbrJ1K",
			},
			AddressCount: 2, SignatureCount: 4,
			Limitation: "Görsel benzerlik ortak kontrol kanıtı değildir.",
		}},
		Evidence: []publicCaseOperationalEvidence{{
			State: "GÖZLENDİ", Class: "observed", Relation: "Cüzdana SOL girişi",
			ObservedAt: "25 Jul 2026", Amount: "0.000001 SOL", Source: "EH11…YJ1K", Destination: "yHCx…6PRe",
			Program: "system", Slot: "435053564", Signature: "dust-signature",
			Classification: "POSSIBLE DUST · ADDRESS POISONING CANDIDATE · GRADE DIŞI", ClassificationClass: "dust",
		}},
	}
	var out bytes.Buffer
	if err := publicCaseOperationalHTML.Execute(&out, data); err != nil {
		t.Fatalf("render operational case: %v", err)
	}
	html := out.String()
	for _, required := range []string{"Vanity adres benzerliği", "Tümünü göster", "EH1*…J1K", "INFERRED küme", "POSSIBLE DUST", "ADDRESS POISONING CANDIDATE", "GRADE DIŞI", "ortak kontrol kanıtı değildir"} {
		if !strings.Contains(html, required) {
			t.Fatalf("missing disclosure marker %q", required)
		}
	}
	if strings.Contains(html, `<details class="technical-details vanity-details" open`) {
		t.Fatal("vanity disclosure must be collapsed by default")
	}
	for _, forbidden := range []string{"aynı kişinin cüzdanı", "aynı sahibin cüzdanı", "kesin ortak kontrol", "<script", "window."} {
		if strings.Contains(strings.ToLower(html), strings.ToLower(forbidden)) {
			t.Fatalf("unsafe vanity claim or executable marker %q", forbidden)
		}
	}
}
