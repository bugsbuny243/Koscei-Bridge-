package handlers

import (
	"database/sql"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

var publicProgramRiskRefPattern = regexp.MustCompile(`^(KDCE1|KDS1)-[0-9a-f]{32}$`)

type publicProgramRisk struct {
	Type                       string    `json:"type"`
	EventRef                   string    `json:"event_ref"`
	PublicURL                  string    `json:"public_url"`
	ProgramID                  string    `json:"program_id"`
	Network                    string    `json:"network"`
	Severity                   string    `json:"severity"`
	RiskTypes                  []string  `json:"risk_types"`
	Summary                    string    `json:"summary"`
	EvidenceRows               int       `json:"evidence_rows"`
	EvidenceHash               string    `json:"evidence_hash"`
	PreviousSnapshotRef        string    `json:"previous_snapshot_ref,omitempty"`
	CurrentSnapshotRef         string    `json:"current_snapshot_ref"`
	PreviousBinaryHash         string    `json:"previous_binary_hash,omitempty"`
	CurrentBinaryHash          string    `json:"current_binary_hash"`
	PreviousUpgradeAuthority   string    `json:"previous_upgrade_authority,omitempty"`
	CurrentUpgradeAuthority    string    `json:"current_upgrade_authority,omitempty"`
	PreviousSourceMatch        string    `json:"previous_source_match,omitempty"`
	CurrentSourceMatch         string    `json:"current_source_match"`
	PreviousLoaderKind         string    `json:"previous_loader_kind,omitempty"`
	CurrentLoaderKind          string    `json:"current_loader_kind"`
	PreviousProgramDataAddress string    `json:"previous_programdata_address,omitempty"`
	CurrentProgramDataAddress  string    `json:"current_programdata_address,omitempty"`
	OccurredAt                 time.Time `json:"occurred_at"`
	VerdictAuthority           bool      `json:"verdict_authority"`
	EvidenceStatus             string    `json:"evidence_status"`
	Limitations                []string  `json:"limitations"`
}

type publicProgramRiskScanner interface {
	Scan(dest ...any) error
}

func scanPublicProgramChange(row publicProgramRiskScanner) (publicProgramRisk, error) {
	var item publicProgramRisk
	var typesRaw []byte
	err := row.Scan(
		&item.EventRef, &item.ProgramID, &item.Network, &typesRaw, &item.Severity, &item.Summary,
		&item.EvidenceHash, &item.OccurredAt, &item.PreviousSnapshotRef, &item.CurrentSnapshotRef,
		&item.PreviousBinaryHash, &item.CurrentBinaryHash, &item.PreviousUpgradeAuthority,
		&item.CurrentUpgradeAuthority, &item.PreviousSourceMatch, &item.CurrentSourceMatch,
		&item.PreviousLoaderKind, &item.CurrentLoaderKind, &item.PreviousProgramDataAddress,
		&item.CurrentProgramDataAddress,
	)
	if err != nil {
		return publicProgramRisk{}, err
	}
	if err := json.Unmarshal(typesRaw, &item.RiskTypes); err != nil {
		return publicProgramRisk{}, err
	}
	item.Type = "program_deployment_changed"
	item.PublicURL = "/program-risk/" + item.EventRef
	item.EvidenceRows = len(item.RiskTypes) + 2
	item.EvidenceStatus = "verified_onchain_state_transition"
	item.VerdictAuthority = false
	item.Limitations = publicProgramRiskLimitations()
	return item, nil
}

func scanPublicProgramSnapshot(row publicProgramRiskScanner) (publicProgramRisk, error) {
	var item publicProgramRisk
	var authorityOpen, executable bool
	err := row.Scan(
		&item.EventRef, &item.ProgramID, &item.Network, &item.CurrentLoaderKind,
		&item.CurrentProgramDataAddress, &item.CurrentUpgradeAuthority, &authorityOpen, &executable,
		&item.CurrentBinaryHash, &item.CurrentSourceMatch, &item.EvidenceHash, &item.OccurredAt,
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
	item.Summary = publicProgramSnapshotRiskSummary(item.RiskTypes)
	item.EvidenceRows = len(item.RiskTypes) + 1
	item.EvidenceStatus = "verified_onchain_program_state"
	item.VerdictAuthority = false
	item.Limitations = publicProgramRiskLimitations()
	return item, nil
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
	return out
}

func publicProgramSnapshotRiskSeverity(types []string) string {
	for _, value := range types {
		if value == "program_not_executable" || value == "source_binary_mismatch" {
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
		return "Dağıtılmış program bytecode'u sağlanan kaynak manifestiyle doğrulanmış biçimde uyuşmuyor ve upgrade authority açık."
	case has("program_not_executable"):
		return "İzlenen program hesabı executable durumunu kaybetmiş görünüyor; program durumu kritik inceleme gerektiriyor."
	case has("source_binary_mismatch"):
		return "Dağıtılmış program bytecode'u sağlanan kaynak manifestiyle doğrulanmış biçimde uyuşmuyor."
	case has("upgrade_authority_open"):
		return "Programın upgrade authority yetkisi açık; program kodu daha sonra değiştirilebilir."
	default:
		return "Doğrulanmış program kontrol riski gözlendi."
	}
}

func publicProgramRiskTitle(item publicProgramRisk) string {
	if item.Type == "program_deployment_changed" {
		return "Solana program dağıtımı değişti"
	}
	return "Solana program kontrol riski"
}

func publicProgramRiskLimitations() []string {
	return []string{
		"Bu yayın zincir üstü teknik program durumunu gösterir; aktör kimliği, niyet, saldırı veya suç isnadı oluşturmaz.",
		"Açık upgrade authority tek başına kötü niyet kanıtı değildir; programın değiştirilebilir olduğunu gösterir.",
		"Kaynak eşleşmesi yalnızca bağımsız manifest sağlandığında değerlendirilebilir; doğrulanmamış kaynak eksikliği uyuşmazlık sayılmaz.",
		"Bu kanıt deterministik karar motoruna otomatik verdict yetkisi vermez.",
	}
}
