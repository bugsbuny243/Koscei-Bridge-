package handlers

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

const publicContractFindingRedactionProfile = "public-contract-finding-v1"

var publicContractFindingRefPattern = regexp.MustCompile(`^KDF1-[0-9a-f]{32}$`)

type contractFindingPublicationRequest struct {
	FindingRef       string `json:"finding_ref"`
	Status           string `json:"status"`
	PublicTitle      string `json:"public_title"`
	PublicSummary    string `json:"public_summary"`
	RedactionProfile string `json:"redaction_profile"`
}

type publicContractFinding struct {
	Type              string    `json:"type"`
	FindingRef        string    `json:"finding_ref"`
	PublicURL         string    `json:"public_url"`
	ProgramID         string    `json:"program_id"`
	Network           string    `json:"network"`
	RuleID            string    `json:"rule_id"`
	Title             string    `json:"title"`
	Summary           string    `json:"summary"`
	Severity          string    `json:"severity"`
	Confidence        string    `json:"confidence"`
	LifecycleStatus   string    `json:"lifecycle_status"`
	DetectorVersion   string    `json:"detector_version"`
	SourceContentHash string    `json:"source_content_hash"`
	EvidenceHash      string    `json:"evidence_hash"`
	EvidenceRows      int       `json:"evidence_rows"`
	EvidenceStatus    string    `json:"evidence_status"`
	RedactionProfile  string    `json:"redaction_profile"`
	PublishedAt       time.Time `json:"published_at"`
	FindingCreatedAt  time.Time `json:"finding_created_at"`
	VerdictAuthority  bool      `json:"verdict_authority"`
	Limitations       []string  `json:"limitations"`
}

type publicContractFindingScanner interface {
	Scan(dest ...any) error
}

func scanPublicContractFinding(row publicContractFindingScanner) (publicContractFinding, error) {
	var item publicContractFinding
	var detailsRaw []byte
	err := row.Scan(
		&item.FindingRef, &item.ProgramID, &item.Network, &item.RuleID,
		&item.Title, &item.Summary, &item.Severity, &item.Confidence,
		&item.LifecycleStatus, &detailsRaw, &item.SourceContentHash,
		&item.RedactionProfile, &item.PublishedAt, &item.FindingCreatedAt,
	)
	if err != nil {
		return publicContractFinding{}, err
	}
	var details map[string]any
	if json.Unmarshal(detailsRaw, &details) == nil {
		item.DetectorVersion = strings.TrimSpace(stringValue(details["detector_version"]))
	}
	item.Type = "contract_finding_published"
	item.PublicURL = "/contract-finding/" + item.FindingRef
	item.EvidenceHash = publicContractFindingEvidenceHash(item)
	item.EvidenceRows = 3
	item.EvidenceStatus = "owner_published_static_observation"
	item.VerdictAuthority = false
	item.Limitations = publicContractFindingLimitations(item)
	return item, nil
}

func publicContractFindingEligible(severity, confidence, lifecycle, artifactTrust string) bool {
	severity = strings.ToLower(strings.TrimSpace(severity))
	confidence = strings.ToLower(strings.TrimSpace(confidence))
	lifecycle = strings.ToLower(strings.TrimSpace(lifecycle))
	artifactTrust = strings.ToLower(strings.TrimSpace(artifactTrust))
	return (severity == "high" || severity == "critical") &&
		confidence != "" && confidence != "unverified" &&
		lifecycle != "" && lifecycle != "rejected" &&
		(artifactTrust == "observed" || artifactTrust == "verified")
}

func publicContractFindingEvidenceHash(item publicContractFinding) string {
	payload := struct {
		FindingRef        string `json:"finding_ref"`
		ProgramID         string `json:"program_id"`
		Network           string `json:"network"`
		RuleID            string `json:"rule_id"`
		Severity          string `json:"severity"`
		Confidence        string `json:"confidence"`
		LifecycleStatus   string `json:"lifecycle_status"`
		DetectorVersion   string `json:"detector_version"`
		SourceContentHash string `json:"source_content_hash"`
		FindingCreatedAt  string `json:"finding_created_at"`
	}{
		FindingRef: item.FindingRef, ProgramID: item.ProgramID, Network: item.Network,
		RuleID: item.RuleID, Severity: item.Severity, Confidence: item.Confidence,
		LifecycleStatus: item.LifecycleStatus, DetectorVersion: item.DetectorVersion,
		SourceContentHash: item.SourceContentHash, FindingCreatedAt: item.FindingCreatedAt.UTC().Format(time.RFC3339Nano),
	}
	encoded, _ := json.Marshal(payload)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func publicContractFindingLimitations(item publicContractFinding) []string {
	out := []string{
		"Bu yayın owner tarafından seçilmiş statik bir güvenlik bulgusudur; çalıştırılabilir exploit veya zincir üstü istismar kanıtı değildir.",
		"Kaynak dosya yolu, eşleşen kod parçası ve özel artifact kimliği public projection içinde redakte edilmiştir.",
		"Bulgular yanlış pozitif içerebilir; erişilebilirlik ve varlık etkisi ayrı kanıt gerektirir.",
		"Bu kayıt deterministik ARVIS verdict veya yatırım notu üretme yetkisine sahip değildir.",
	}
	if item.Confidence == "reproduced" || item.Confidence == "verified" || item.LifecycleStatus == "impact_confirmed" {
		out[0] = "Bu yayın owner tarafından seçilmiş güvenlik bulgusudur; kapsam ve etki yalnız yayımlanan güven/lifecycle seviyesi kadar desteklenir."
	}
	return out
}

func defaultPublicContractFindingTitle(ruleID, title string) string {
	title = boundedPublicDossierText(title, 140)
	if title == "" {
		title = "Akıllı kontrat güvenlik bulgusu"
	}
	if strings.TrimSpace(ruleID) == "" {
		return title
	}
	return boundedPublicDossierText(strings.TrimSpace(ruleID)+" · "+title, 180)
}

func defaultPublicContractFindingSummary(severity, confidence, lifecycle string) string {
	return boundedPublicDossierText(
		"Statik analiz "+strings.ToUpper(strings.TrimSpace(severity))+" önem seviyesinde bir güvenlik yüzeyi gözlemledi. Güven: "+
			strings.TrimSpace(confidence)+"; yaşam döngüsü: "+strings.TrimSpace(lifecycle)+
			". Bu yayın exploit veya kötüye kullanım iddiası değildir.", 1200)
}

func publicContractFindingPublicationAction(exists bool, previousStatus, nextStatus string) string {
	if !exists {
		if nextStatus == "public" {
			return "published"
		}
		return "created"
	}
	if previousStatus != nextStatus {
		switch nextStatus {
		case "public":
			return "published"
		case "hidden":
			return "hidden"
		case "draft":
			return "drafted"
		}
	}
	return "updated"
}

func publicContractFindingNotFound(err error) bool {
	return err == sql.ErrNoRows
}
