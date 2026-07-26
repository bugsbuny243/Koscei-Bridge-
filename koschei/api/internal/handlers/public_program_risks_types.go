package handlers

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
)

var publicProgramRiskRefPattern = regexp.MustCompile(`^(KDCE1|KDS1)-[0-9a-f]{32}$`)

type publicProgramRisk struct {
	Type                       string         `json:"type"`
	EventRef                   string         `json:"event_ref"`
	PublicURL                  string         `json:"public_url"`
	Title                      string         `json:"title"`
	Decision                   string         `json:"decision"`
	RecommendedAction          string         `json:"recommended_action"`
	ProgramID                  string         `json:"program_id"`
	Network                    string         `json:"network"`
	Severity                   string         `json:"severity"`
	LifecycleStatus            string         `json:"lifecycle_status"`
	RiskTypes                  []string       `json:"risk_types"`
	Summary                    string         `json:"summary"`
	EvidenceRows               int            `json:"evidence_rows"`
	EvidenceRefs               []string       `json:"evidence_refs"`
	VerificationSchema         string         `json:"verification_schema"`
	VerificationPayload        map[string]any `json:"verification_payload"`
	VerificationHash           string         `json:"verification_hash"`
	PreviousSnapshotRef        string         `json:"previous_snapshot_ref,omitempty"`
	CurrentSnapshotRef         string         `json:"current_snapshot_ref"`
	PreviousBinaryHash         string         `json:"previous_binary_hash,omitempty"`
	CurrentBinaryHash          string         `json:"current_binary_hash"`
	PreviousUpgradeAuthority   string         `json:"previous_upgrade_authority,omitempty"`
	CurrentUpgradeAuthority    string         `json:"current_upgrade_authority,omitempty"`
	PreviousSourceMatch        string         `json:"previous_source_match,omitempty"`
	CurrentSourceMatch         string         `json:"current_source_match"`
	PreviousLoaderKind         string         `json:"previous_loader_kind,omitempty"`
	CurrentLoaderKind          string         `json:"current_loader_kind"`
	PreviousProgramDataAddress string         `json:"previous_programdata_address,omitempty"`
	CurrentProgramDataAddress  string         `json:"current_programdata_address,omitempty"`
	OccurredAt                 time.Time      `json:"occurred_at"`
	VerdictAuthority           bool           `json:"verdict_authority"`
	EvidenceStatus             string         `json:"evidence_status"`
	Limitations                []string       `json:"limitations"`
}

type publicProgramRiskScanner interface {
	Scan(dest ...any) error
}

func scanPublicProgramChange(row publicProgramRiskScanner) (publicProgramRisk, error) {
	var item publicProgramRisk
	var typesRaw, evidenceRaw []byte
	var currentAuthorityOpen, currentExecutable bool
	var publicTitle, publicSummary string
	err := row.Scan(
		&item.EventRef, &item.ProgramID, &item.Network, &typesRaw, &item.Severity, &item.Summary,
		&item.OccurredAt, &item.PreviousSnapshotRef, &item.CurrentSnapshotRef,
		&item.PreviousBinaryHash, &item.CurrentBinaryHash, &item.PreviousUpgradeAuthority,
		&item.CurrentUpgradeAuthority, &item.PreviousSourceMatch, &item.CurrentSourceMatch,
		&item.PreviousLoaderKind, &item.CurrentLoaderKind, &item.PreviousProgramDataAddress,
		&item.CurrentProgramDataAddress, &currentAuthorityOpen, &currentExecutable, &evidenceRaw,
		&publicTitle, &publicSummary,
	)
	if err != nil {
		return publicProgramRisk{}, err
	}
	var changeTypes []string
	if err := json.Unmarshal(typesRaw, &changeTypes); err != nil {
		return publicProgramRisk{}, err
	}
	item.RiskTypes = uniquePublicStrings(append(publicProgramChainChangeTypes(changeTypes), publicProgramSnapshotRiskTypes(currentAuthorityOpen, currentExecutable, item.CurrentSourceMatch)...))
	if len(item.RiskTypes) == 0 {
		return publicProgramRisk{}, sql.ErrNoRows
	}
	item.Type = "program_deployment_changed"
	item.PublicURL = "/program-risk/" + item.EventRef
	item.LifecycleStatus = "observed_change"
	item.EvidenceStatus = "verified_onchain_state_transition"
	item.VerdictAuthority = false
	item.EvidenceRefs = publicProgramEvidenceRefs(evidenceRaw)
	item.EvidenceRows = len(item.EvidenceRefs)
	if publicTitle != "" {
		item.Title = publicTitle
	} else {
		item.Title = "Solana program dağıtımı değişti"
	}
	if publicSummary != "" {
		item.Summary = publicSummary
	}
	if publicProgramSnapshotRiskSeverity(item.RiskTypes) == "critical" {
		item.Severity = "critical"
	}
	item.Limitations = publicProgramRiskLimitations()
	return finalizePublicProgramRisk(item), nil
}

func scanPublicProgramSnapshot(row publicProgramRiskScanner) (publicProgramRisk, error) {
	var item publicProgramRisk
	var authorityOpen, executable bool
	var evidenceRaw []byte
	var publicTitle, publicSummary string
	err := row.Scan(
		&item.EventRef, &item.ProgramID, &item.Network, &item.CurrentLoaderKind,
		&item.CurrentProgramDataAddress, &item.CurrentUpgradeAuthority, &authorityOpen, &executable,
		&item.CurrentBinaryHash, &item.CurrentSourceMatch, &item.OccurredAt, &evidenceRaw,
		&publicTitle, &publicSummary,
	)
	if err != nil {
		return publicProgramRisk{}, err
	}
	item.RiskTypes = publicProgramSnapshotRiskTypes(authorityOpen, executable, item.CurrentSourceMatch)
	if len(item.RiskTypes) == 0 {
		return publicProgramRisk{}, sql.ErrNoRows
	}
	item.Type = "program_control_risk_observed"
	item.CurrentSnapshotRef = item.EventRef
	item.PublicURL = "/program-risk/" + item.EventRef
	item.Severity = publicProgramSnapshotRiskSeverity(item.RiskTypes)
	item.LifecycleStatus = "current"
	if publicTitle != "" {
		item.Title = publicTitle
	} else {
		item.Title = "Solana program kontrol riski"
	}
	if publicSummary != "" {
		item.Summary = publicSummary
	} else {
		item.Summary = publicProgramSnapshotRiskSummary(item.RiskTypes)
	}
	item.EvidenceStatus = "verified_onchain_program_state"
	item.VerdictAuthority = false
	item.EvidenceRefs = publicProgramEvidenceRefs(evidenceRaw)
	item.EvidenceRows = len(item.EvidenceRefs)
	item.Limitations = publicProgramRiskLimitations()
	return finalizePublicProgramRisk(item), nil
}

func finalizePublicProgramRisk(item publicProgramRisk) publicProgramRisk {
	item.RiskTypes = uniquePublicStrings(item.RiskTypes)
	if item.Severity == "critical" {
		item.Decision = "BLOCK"
		item.RecommendedAction = "Bu programla etkileşimi durdur. Güncel program hash, authority ve kaynak eşleşmesi doğrulanmadan işlem imzalama."
	} else {
		item.Decision = "WARN"
		item.RecommendedAction = "İşlemi beklet. Programın upgrade authority ve son dağıtım durumunu bağımsız olarak doğrula."
	}
	item.EvidenceRefs = uniquePublicStrings(item.EvidenceRefs)
	item.VerificationSchema = "koschei-public-program-risk-v1"
	item.VerificationPayload = map[string]any{
		"schema":                       item.VerificationSchema,
		"type":                         item.Type,
		"event_ref":                    item.EventRef,
		"program_id":                   item.ProgramID,
		"network":                      item.Network,
		"severity":                     item.Severity,
		"decision":                     item.Decision,
		"recommended_action":           item.RecommendedAction,
		"lifecycle_status":             item.LifecycleStatus,
		"risk_types":                   item.RiskTypes,
		"summary":                      item.Summary,
		"evidence_refs":                item.EvidenceRefs,
		"previous_snapshot_ref":        item.PreviousSnapshotRef,
		"current_snapshot_ref":         item.CurrentSnapshotRef,
		"previous_binary_hash":         item.PreviousBinaryHash,
		"current_binary_hash":          item.CurrentBinaryHash,
		"previous_upgrade_authority":   item.PreviousUpgradeAuthority,
		"current_upgrade_authority":    item.CurrentUpgradeAuthority,
		"previous_source_match":        item.PreviousSourceMatch,
		"current_source_match":         item.CurrentSourceMatch,
		"previous_loader_kind":         item.PreviousLoaderKind,
		"current_loader_kind":          item.CurrentLoaderKind,
		"previous_programdata_address": item.PreviousProgramDataAddress,
		"current_programdata_address":  item.CurrentProgramDataAddress,
		"occurred_at":                  item.OccurredAt.UTC().Format(time.RFC3339Nano),
		"verdict_authority":            false,
	}
	encoded, _ := json.Marshal(item.VerificationPayload)
	digest := sha256.Sum256(encoded)
	item.VerificationHash = "sha256:" + hex.EncodeToString(digest[:])
	return item
}

func publicProgramChainChangeTypes(values []string) []string {
	allowed := map[string]bool{
		"loader_changed":              true,
		"programdata_address_changed": true,
		"bytecode_changed":            true,
		"upgrade_authority_opened":    true,
		"upgrade_authority_changed":   true,
	}
	out := []string{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if allowed[value] {
			out = append(out, value)
		}
	}
	return uniquePublicStrings(out)
}

func publicProgramSnapshotRiskTypes(authorityOpen, executable bool, matchStatus string) []string {
	out := []string{}
	if !executable {
		out = append(out, "program_not_executable")
	}
	if strings.EqualFold(strings.TrimSpace(matchStatus), "mismatched") {
		out = append(out, "source_binary_mismatch")
	}
	if authorityOpen {
		out = append(out, "upgrade_authority_open")
	}
	return uniquePublicStrings(out)
}

func publicProgramSnapshotRiskSeverity(types []string) string {
	for _, value := range types {
		if value == "program_not_executable" || value == "source_binary_mismatch" || value == "bytecode_changed" || value == "loader_changed" || value == "programdata_address_changed" {
			return "critical"
		}
	}
	return "high"
}

func publicProgramSnapshotRiskSummary(types []string) string {
	has := func(want string) bool {
		for _, value := range types {
			if value == want {
				return true
			}
		}
		return false
	}
	switch {
	case has("source_binary_mismatch") && has("upgrade_authority_open"):
		return "Dağıtılmış program bytecode'u sağlanan kaynak manifestiyle uyuşmuyor ve programın upgrade authority yetkisi açık."
	case has("program_not_executable"):
		return "Güncel zincir gözleminde program hesabı executable değil."
	case has("source_binary_mismatch"):
		return "Dağıtılmış program bytecode'u sağlanan kaynak manifestiyle uyuşmuyor."
	case has("upgrade_authority_open"):
		return "Programın upgrade authority yetkisi açık; program kodu daha sonra değiştirilebilir."
	default:
		return "Doğrulanmış program kontrol riski gözlendi."
	}
}

func publicProgramEvidenceRefs(raw []byte) []string {
	var refs []string
	_ = json.Unmarshal(raw, &refs)
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if strings.HasPrefix(ref, "artifact:") || ref == "" {
			continue
		}
		out = append(out, ref)
	}
	return uniquePublicStrings(out)
}

func uniquePublicStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
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

func publicProgramRiskLimitations() []string {
	return []string{
		"Bu yayın zincir üstü teknik program durumunu gösterir; aktör kimliği, niyet, saldırı veya suç isnadı oluşturmaz.",
		"Açık upgrade authority tek başına kötü niyet kanıtı değildir; programın değiştirilebilir olduğunu gösterir.",
		"Kaynak eşleşmesi yalnızca bağımsız manifest sağlandığında değerlendirilir; kaynak eksikliği uyuşmazlık sayılmaz.",
		"Bu kanıt deterministik karar motoruna otomatik verdict yetkisi vermez.",
	}
}
