package handlers

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const (
	programSecurityPumpFun  = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
	programSecurityPumpSwap = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"
	arvisLegacyLoaderV2ID   = "BPFLoader2111111111111111111111111111111111"
	arvisLegacyLoaderV1ID   = "BPFLoader1111111111111111111111111111111111"
)

type programSecurityCandidate struct {
	ProgramID string
	Role      string
}

type arvisProgramAuthoritySnapshot struct {
	Status               string
	LoaderID             string
	LoaderKind           string
	ProgramDataAddress   string
	AccountSlot          uint64
	DeploymentSlot       uint64
	UpgradeAuthority     string
	UpgradeAuthorityOpen bool
	Immutable            bool
	EvidenceRefs         []string
	Limitations          []string
}

type arvisProgramAccountInfoResponse struct {
	Context struct {
		Slot uint64 `json:"slot"`
	} `json:"context"`
	Value *struct {
		Owner      string   `json:"owner"`
		Executable bool     `json:"executable"`
		Data       []string `json:"data"`
	} `json:"value"`
}

func (h *Handler) collectProgramSecuritySurface(ctx context.Context, network string, source map[string]any, lp services.LPControlEvidence, market services.TokenMarketSnapshot) services.ProgramSecuritySurface {
	if h == nil {
		return newProgramSecuritySurface("rpc_unavailable")
	}
	return collectProgramSecuritySurface(ctx, h.lpRPC(), network, source, lp, market)
}

func collectProgramSecuritySurface(ctx context.Context, rpc solanaRPCCall, network string, source map[string]any, lp services.LPControlEvidence, market services.TokenMarketSnapshot) services.ProgramSecuritySurface {
	out := newProgramSecuritySurface("no_observed_program_candidates")
	candidates := programSecurityCandidates(source, lp, market)
	if len(candidates) == 0 {
		return out
	}
	if rpc == nil {
		out.Status = "rpc_unavailable"
		return out
	}
	authorityComplete := true
	ageComplete := true
	availableCount := 0
	for _, candidate := range candidates {
		item := services.ProgramSecurityEvidence{
			Role: candidate.Role, ProgramID: candidate.ProgramID,
			Status: "inspection_failed", AgeSemantics: "latest ProgramData deployment or upgrade age; not original program creation age",
			EvidenceRefs: []string{}, Limitations: []string{},
		}
		snapshot, err := inspectARVISProgramAuthority(ctx, rpc, network, candidate.ProgramID)
		if err != nil {
			authorityComplete = false
			ageComplete = false
			item.Limitations = append(item.Limitations, compactCollectorError(err))
			out.Programs = append(out.Programs, item)
			continue
		}
		item.Available = true
		availableCount++
		item.Status = snapshot.Status
		item.LoaderID = snapshot.LoaderID
		item.LoaderKind = snapshot.LoaderKind
		item.ProgramDataAddress = snapshot.ProgramDataAddress
		item.AccountSlot = snapshot.AccountSlot
		item.DeploymentSlot = snapshot.DeploymentSlot
		item.UpgradeAuthority = snapshot.UpgradeAuthority
		item.UpgradeAuthorityOpen = snapshot.UpgradeAuthorityOpen
		item.Immutable = snapshot.Immutable
		item.EvidenceRefs = append(item.EvidenceRefs, snapshot.EvidenceRefs...)
		item.Limitations = append(item.Limitations, snapshot.Limitations...)
		if snapshot.DeploymentSlot > 0 {
			var blockTime *int64
			if blockErr := rpc(ctx, network, "getBlockTime", []any{snapshot.DeploymentSlot}, &blockTime); blockErr == nil && blockTime != nil && *blockTime > 0 {
				observed := time.Unix(*blockTime, 0).UTC()
				item.LastDeploymentAt = &observed
				if !observed.After(time.Now().UTC()) {
					item.AgeAvailable = true
					item.LastDeploymentAgeDays = math.Round(time.Since(observed).Hours()/24*100) / 100
				}
				item.EvidenceRefs = append(item.EvidenceRefs, "rpc:getBlockTime")
			} else {
				ageComplete = false
				item.Limitations = append(item.Limitations, "Deployment slot was verified but its block time was unavailable.")
			}
		} else {
			ageComplete = false
		}
		out.Programs = append(out.Programs, item)
	}
	out.Available = availableCount > 0
	out.AuthorityCoverageComplete = authorityComplete
	out.AgeCoverageComplete = ageComplete
	switch {
	case availableCount == 0:
		out.Status = "inspection_failed"
	case authorityComplete && ageComplete:
		out.Status = "complete"
	case authorityComplete:
		out.Status = "authority_complete_age_partial"
	default:
		out.Status = "partial"
	}
	return out
}

// inspectARVISProgramAuthority is a narrow ARVIS evidence collector. It keeps
// upgrade-authority facts used by actor/token investigations without depending
// on the separately gated Defense OS deployment subsystem.
func inspectARVISProgramAuthority(ctx context.Context, rpc solanaRPCCall, network, programID string) (arvisProgramAuthoritySnapshot, error) {
	programID = strings.TrimSpace(programID)
	if rpc == nil {
		return arvisProgramAuthoritySnapshot{}, errors.New("solana rpc unavailable")
	}
	if programID == "" {
		return arvisProgramAuthoritySnapshot{}, errors.New("program_id is required")
	}
	read := func(address string, length int) (arvisProgramAccountInfoResponse, error) {
		var result arvisProgramAccountInfoResponse
		config := map[string]any{"encoding": "base64", "commitment": "confirmed", "dataSlice": map[string]any{"offset": 0, "length": length}}
		if err := rpc(ctx, network, "getAccountInfo", []any{address, config}, &result); err != nil {
			return result, err
		}
		return result, nil
	}

	program, err := read(programID, 45)
	if err != nil {
		return arvisProgramAuthoritySnapshot{}, fmt.Errorf("program account lookup failed: %w", err)
	}
	if program.Value == nil {
		return arvisProgramAuthoritySnapshot{}, errors.New("program account not found")
	}
	if !program.Value.Executable {
		return arvisProgramAuthoritySnapshot{}, errors.New("program account is not executable")
	}
	out := arvisProgramAuthoritySnapshot{
		LoaderID: strings.TrimSpace(program.Value.Owner), AccountSlot: program.Context.Slot,
		EvidenceRefs: []string{"rpc:getAccountInfo:" + programID}, Limitations: []string{},
	}
	programHeader, decodeErr := decodeARVISProgramAccountData(program.Value.Data)
	if decodeErr != nil {
		return arvisProgramAuthoritySnapshot{}, fmt.Errorf("program account decode failed: %w", decodeErr)
	}

	switch out.LoaderID {
	case arvisUpgradeableLoaderID:
		out.LoaderKind = "bpf_upgradeable_loader"
		if len(programHeader) < 36 || binary.LittleEndian.Uint32(programHeader[:4]) != 2 {
			return arvisProgramAuthoritySnapshot{}, errors.New("invalid upgradeable program account header")
		}
		out.ProgramDataAddress = arvisProgramBase58Encode(programHeader[4:36])
		programData, lookupErr := read(out.ProgramDataAddress, 45)
		if lookupErr != nil {
			return arvisProgramAuthoritySnapshot{}, fmt.Errorf("programdata lookup failed: %w", lookupErr)
		}
		if programData.Value == nil || strings.TrimSpace(programData.Value.Owner) != arvisUpgradeableLoaderID {
			return arvisProgramAuthoritySnapshot{}, errors.New("programdata account owner mismatch")
		}
		header, decodeErr := decodeARVISProgramAccountData(programData.Value.Data)
		if decodeErr != nil {
			return arvisProgramAuthoritySnapshot{}, fmt.Errorf("programdata decode failed: %w", decodeErr)
		}
		if len(header) < 45 || binary.LittleEndian.Uint32(header[:4]) != 3 {
			return arvisProgramAuthoritySnapshot{}, errors.New("invalid upgradeable ProgramData header")
		}
		out.DeploymentSlot = binary.LittleEndian.Uint64(header[4:12])
		switch header[12] {
		case 0:
			out.Immutable = true
			out.Status = "immutable_upgradeable_program"
		case 1:
			out.UpgradeAuthority = arvisProgramBase58Encode(header[13:45])
			out.UpgradeAuthorityOpen = true
			out.Status = "upgrade_authority_open"
		default:
			return arvisProgramAuthoritySnapshot{}, errors.New("invalid upgrade authority option tag")
		}
		out.EvidenceRefs = append(out.EvidenceRefs, "rpc:getAccountInfo:"+out.ProgramDataAddress)
		out.Limitations = append(out.Limitations, "Deployment slot is the latest deployment or upgrade recorded in ProgramData, not proof of the original creation slot.")
	case arvisLegacyLoaderV2ID:
		out.LoaderKind = "bpf_loader_v2"
		out.Status = "immutable_legacy_loader"
		out.Immutable = true
		out.Limitations = append(out.Limitations, "Legacy loader metadata does not expose a ProgramData deployment slot or upgrade authority.")
	case arvisLegacyLoaderV1ID:
		out.LoaderKind = "bpf_loader_v1"
		out.Status = "immutable_legacy_loader"
		out.Immutable = true
		out.Limitations = append(out.Limitations, "Legacy loader metadata does not expose a ProgramData deployment slot or upgrade authority.")
	default:
		return arvisProgramAuthoritySnapshot{}, fmt.Errorf("unsupported program loader: %s", out.LoaderID)
	}
	return out, nil
}

func decodeARVISProgramAccountData(value []string) ([]byte, error) {
	if len(value) != 2 || value[1] != "base64" {
		return nil, errors.New("account data is not base64 encoded")
	}
	decoded, err := base64.StdEncoding.DecodeString(value[0])
	if err != nil {
		return nil, err
	}
	if len(decoded) == 0 {
		return nil, errors.New("account data is empty")
	}
	return decoded, nil
}

func arvisProgramBase58Encode(input []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	if len(input) == 0 {
		return ""
	}
	digits := []byte{}
	for _, value := range input {
		carry := int(value)
		for i := 0; i < len(digits); i++ {
			carry += int(digits[i]) << 8
			digits[i] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, byte(carry%58))
			carry /= 58
		}
	}
	for _, value := range input {
		if value != 0 {
			break
		}
		digits = append(digits, 0)
	}
	var builder strings.Builder
	for i := len(digits) - 1; i >= 0; i-- {
		builder.WriteByte(alphabet[digits[i]])
	}
	return builder.String()
}

func newProgramSecuritySurface(status string) services.ProgramSecuritySurface {
	return services.ProgramSecuritySurface{
		Status: status, Programs: []services.ProgramSecurityEvidence{}, ObservedAt: time.Now().UTC(),
		EvidencePolicy: "upgrade authority is a capability fact, not proof of intent; age means latest deployment or upgrade age",
		Limitations:    []string{},
	}
}

func programSecurityCandidates(source map[string]any, lp services.LPControlEvidence, market services.TokenMarketSnapshot) []programSecurityCandidate {
	out := []programSecurityCandidate{}
	add := func(programID, role string) {
		programID = strings.TrimSpace(programID)
		if len(programID) < 32 || len(programID) > 44 {
			return
		}
		for _, existing := range out {
			if existing.ProgramID == programID {
				return
			}
		}
		if len(out) < 4 {
			out = append(out, programSecurityCandidate{ProgramID: programID, Role: role})
		}
	}
	add(lp.PoolProgram, "liquidity_pool_program")
	launchPlatform := strings.ToLower(strings.TrimSpace(creatorIntelCleanString(source["launch_platform"])))
	if strings.Contains(launchPlatform, "pump") {
		add(programSecurityPumpFun, "launch_program")
	}
	if strings.Contains(strings.ToLower(market.BestPairDEX), "pump") {
		add(programSecurityPumpSwap, "liquidity_pool_program")
	}
	if signals, ok := source["signals"].(map[string]any); ok {
		for _, key := range []string{"program_id", "program", "launch_program", "pool_program", "bonding_curve_program"} {
			add(creatorIntelCleanString(signals[key]), "source_observed_program")
		}
	}
	return out
}
