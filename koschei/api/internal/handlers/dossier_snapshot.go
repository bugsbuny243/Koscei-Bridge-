package handlers

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// persistDossierSourceSnapshot freezes the exact signed technical report. It is
// best-effort for the scan path; export never rescans when a snapshot is absent.
func (h *Handler) persistDossierSourceSnapshot(ctx context.Context, report map[string]any) error {
	if h == nil || report == nil {
		return nil
	}

	// The canonical actor engine already collected and persisted creator evidence.
	// Project that same result to stable top-level fields for API/UI consumers;
	// never start a second RPC crawl merely to populate presentation aliases.
	attachCreatorReportProjections(report)

	if _, attached := report["defense_agent_runtime"]; !attached {
		target := dossierSnapshotTarget(report)
		network := firstNonEmptyString(dossierString(report["network"]), "solana-mainnet")
		generatedAt := dossierParseTime(dossierString(report["generated_at"]))
		if generatedAt.IsZero() {
			generatedAt = time.Now().UTC()
		}
		h.attachDefenseAgentRuntime(ctx, report, target, network, generatedAt)
	}

	// Diagnostics mutate the exact canonical report before hashing. Wallet targets
	// never fabricate token-only ARVIS coverage; token targets keep the complete
	// token + actor reachability contract.
	if isActorDossierReport(report) {
		attachCanonicalWalletIntegrationCoverage(report)
	} else {
		attachCanonicalInvestigationDiagnostics(report)
	}

	if h.DB == nil {
		return nil
	}
	final := dossierMap(report["final_verdict"])
	verdictSignature := strings.TrimSpace(dossierString(final["signature"]))
	if verdictSignature == "" || !dossierBool(final["signed"]) {
		return nil
	}
	target := dossierSnapshotTarget(report)
	if target == "" {
		return nil
	}
	network := firstNonEmptyString(dossierString(report["network"]), "solana-mainnet")
	ruleset := strings.TrimSpace(dossierString(final["ruleset_version"]))
	if ruleset == "" {
		return errDossierSourceIncomplete
	}
	producedAt := dossierParseTime(firstNonEmptyString(dossierString(final["generated_at"]), dossierString(report["generated_at"])))
	if producedAt.IsZero() {
		return errDossierSourceIncomplete
	}
	canonical, err := json.Marshal(report)
	if err != nil {
		return err
	}
	sourceHash := dossierSHA256(canonical)
	snapshotIdentity := dossierSnapshotIdentity(report, verdictSignature)
	verdictID := strings.TrimSpace(dossierString(final["id"]))
	if verdictID == "" && isActorDossierReport(report) {
		verdictID = verdictSignature
	}
	_, err = h.DB.ExecContext(ctx, `
		INSERT INTO dossier_source_snapshots
		(mint,network,verdict_id,verdict_signature,ruleset_version,produced_at,source_hash,canonical_source,source_payload)
		VALUES ($1,$2,NULLIF($3,''),$4,$5,$6,$7,$8,$9::jsonb)
		ON CONFLICT (verdict_signature) DO NOTHING`,
		target, network, verdictID, snapshotIdentity, ruleset, producedAt.UTC(), sourceHash, canonical, string(canonical),
	)
	return err
}

func dossierSnapshotTarget(report map[string]any) string {
	if isActorDossierReport(report) {
		if wallet := strings.TrimSpace(dossierString(report["wallet"])); wallet != "" {
			return wallet
		}
	}
	return strings.TrimSpace(dossierString(report["target"]))
}

func dossierSnapshotIdentity(report map[string]any, verdictSignature string) string {
	verdictSignature = strings.TrimSpace(verdictSignature)
	if !isActorDossierReport(report) {
		return verdictSignature
	}
	acceptanceHash := strings.TrimSpace(dossierString(dossierMap(report["actor_acceptance"])["acceptance_hash"]))
	if acceptanceHash == "" {
		return verdictSignature
	}
	identity := dossierSHA256([]byte(verdictSignature + "\n" + acceptanceHash))
	return "actor-case:" + strings.TrimPrefix(identity, "sha256:")
}

func attachCreatorReportProjections(report map[string]any) {
	if report == nil || isActorDossierReport(report) {
		return
	}
	actor := dossierMap(report["actor_investigation"])
	wallet := strings.TrimSpace(dossierString(actor["wallet"]))

	if _, exists := report["creator_intelligence"]; !exists {
		if wallet == "" {
			report["creator_intelligence"] = map[string]any{
				"available": false,
				"status": "creator_wallet_not_observed",
				"creator_wallet": "",
			}
		} else {
			run := canonicalProjectionMap(actor["integration_run"])
			status := firstNonEmptyString(
				dossierString(run["status"]),
				dossierString(actor["store_status"]),
				"observed",
			)
			report["creator_intelligence"] = map[string]any{
				"available": true,
				"status": status,
				"creator_wallet": wallet,
				"dossier": actor["dossier"],
				"rule_verdict": actor["rule_verdict"],
				"integration_run": actor["integration_run"],
				"external_discovery": actor["external_discovery"],
				"funding_origin": actor["funding_origin"],
				"actor_live_evidence": actor["actor_live_evidence"],
				"source": "canonical_actor_investigation",
			}
		}
	}

	if _, exists := report["creator_distribution"]; exists {
		return
	}
	distribution, exists := actor["current_token_distribution"]
	if !exists || distribution == nil {
		report["creator_distribution"] = map[string]any{
			"available": false,
			"status": "creator_mint_relation_not_resolved",
		}
		return
	}
	distributionMap := canonicalProjectionMap(distribution)
	status := firstNonEmptyString(dossierString(distributionMap["status"]), "not_requested")
	available := status != "not_requested" &&
		status != "creator_mint_relation_unavailable" &&
		status != "creator_mint_relation_unresolved" &&
		status != "persistence_unavailable"
	report["creator_distribution"] = map[string]any{
		"available": available,
		"status": status,
		"report": distribution,
		"source": "canonical_actor_distribution",
	}
}

func canonicalProjectionMap(value any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if mapped, ok := value.(map[string]any); ok && mapped != nil {
		return mapped
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return map[string]any{}
	}
	mapped := map[string]any{}
	if json.Unmarshal(encoded, &mapped) != nil {
		return map[string]any{}
	}
	return mapped
}

func (h *Handler) loadDossierSnapshot(ctx context.Context, mint, verdictID string) (dossierSnapshot, error) {
	if h == nil || h.DB == nil {
		return dossierSnapshot{}, errDossierSourceIncomplete
	}
	query := `
		SELECT id::text,mint,network,COALESCE(verdict_id,''),verdict_signature,
		       ruleset_version,produced_at,source_hash,canonical_source
		FROM dossier_source_snapshots
		WHERE mint=$1`
	args := []any{strings.TrimSpace(mint)}
	if strings.TrimSpace(verdictID) != "" {
		query += ` AND (id::text=$2 OR verdict_id=$2 OR verdict_signature=$2)`
		args = append(args, strings.TrimSpace(verdictID))
	}
	query += ` ORDER BY produced_at DESC,id DESC LIMIT 1`
	var snapshot dossierSnapshot
	var canonical []byte
	if err := h.DB.QueryRowContext(ctx, query, args...).Scan(
		&snapshot.ID, &snapshot.Mint, &snapshot.Network, &snapshot.VerdictID,
		&snapshot.VerdictSignature, &snapshot.RulesetVersion, &snapshot.ProducedAt,
		&snapshot.SourceHash, &canonical,
	); err != nil {
		return dossierSnapshot{}, errDossierSourceIncomplete
	}
	if dossierSHA256(canonical) != snapshot.SourceHash {
		return dossierSnapshot{}, errDossierSourceHash
	}
	if json.Unmarshal(canonical, &snapshot.Report) != nil || snapshot.Report == nil {
		return dossierSnapshot{}, errDossierSourceIncomplete
	}
	return snapshot, nil
}
