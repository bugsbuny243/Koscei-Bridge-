from pathlib import Path
import re

ROOT = Path('koschei/api')


def replace_once(path, old, new):
    p = ROOT / path
    text = p.read_text()
    if text.count(old) != 1:
        raise SystemExit(f'{path}: expected exactly one match, got {text.count(old)}')
    p.write_text(text.replace(old, new, 1))


def regex_once(path, pattern, replacement):
    p = ROOT / path
    text = p.read_text()
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f'{path}: regex expected one match, got {count}')
    p.write_text(updated)


upsert = r'''func (s *ActorDefenseStore) UpsertEvidence(ctx context.Context, item ActorDefenseEvidenceRecord) error {
	if s == nil || s.DB == nil {
		return fmt.Errorf("actor defense database is unavailable")
	}
	item.Network = normalizeRadarNetwork(item.Network)
	item.ActorWallet = strings.TrimSpace(item.ActorWallet)
	item.CounterpartKind = strings.TrimSpace(item.CounterpartKind)
	item.CounterpartID = strings.TrimSpace(item.CounterpartID)
	item.Relation = strings.TrimSpace(item.Relation)
	item.EvidenceKey = strings.TrimSpace(item.EvidenceKey)
	item.Source = strings.TrimSpace(item.Source)
	item.Signature = strings.TrimSpace(item.Signature)
	item.TokenMint = strings.TrimSpace(item.TokenMint)
	item.VerificationStatus = normalizeActorEvidenceStatus(item.VerificationStatus)
	if item.Source == "" {
		item.Source = "solana_rpc"
	}
	if item.ObservedAt.IsZero() {
		item.ObservedAt = time.Now().UTC()
	}
	if item.ActorWallet == "" || item.CounterpartKind == "" || item.CounterpartID == "" || item.Relation == "" || item.EvidenceKey == "" {
		return fmt.Errorf("actor evidence is incomplete")
	}
	metadata, err := json.Marshal(nonNilMap(item.Metadata))
	if err != nil {
		return fmt.Errorf("encode actor evidence metadata: %w", err)
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO security_actor_evidence
			(network,actor_wallet,counterpart_kind,counterpart_id,relation,verification_status,
			 evidence_key,source,signature,slot,observed_at,amount_native,token_mint,token_amount,
			 occurrence_count,metadata,created_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),NULLIF($10,0),$11,$12,NULLIF($13,''),$14,1,$15::jsonb,now(),now())
		ON CONFLICT (network,actor_wallet,counterpart_kind,counterpart_id,relation,source,evidence_key)
		DO UPDATE SET
			verification_status=CASE
				WHEN security_actor_evidence.verification_status='verified' THEN 'verified'
				ELSE EXCLUDED.verification_status
			END,
			signature=COALESCE(EXCLUDED.signature,security_actor_evidence.signature),
			slot=COALESCE(EXCLUDED.slot,security_actor_evidence.slot),
			observed_at=GREATEST(security_actor_evidence.observed_at,EXCLUDED.observed_at),
			amount_native=GREATEST(security_actor_evidence.amount_native,EXCLUDED.amount_native),
			token_mint=COALESCE(EXCLUDED.token_mint,security_actor_evidence.token_mint),
			token_amount=GREATEST(security_actor_evidence.token_amount,EXCLUDED.token_amount),
			occurrence_count=security_actor_evidence.occurrence_count+1,
			metadata=security_actor_evidence.metadata || EXCLUDED.metadata,
			updated_at=now()`,
		item.Network, item.ActorWallet, item.CounterpartKind, item.CounterpartID, item.Relation,
		item.VerificationStatus, item.EvidenceKey, item.Source, item.Signature, item.Slot,
		item.ObservedAt.UTC(), item.AmountNative, item.TokenMint, item.TokenAmount, string(metadata))
	if err != nil {
		return err
	}
	if event, ok := actorExitEventFromEvidence(item); ok {
		if err := upsertActorExitEventTx(ctx, tx, event); err != nil {
			return err
		}
	}
	return tx.Commit()
}
'''
regex_once(
    'internal/services/actor_defense_store.go',
    r'func \(s \*ActorDefenseStore\) UpsertEvidence\(ctx context\.Context, item ActorDefenseEvidenceRecord\) error \{.*?\n\}\n\n(?=func \(s \*ActorDefenseStore\) upsertTrack)',
    upsert + '\n',
)

# Load exit-event recurrence after lifecycle recurrence and feed the same repeat-actor arm.
replace_once(
    'internal/handlers/unified_investigation_report.go',
    '''\t// Token-scoped live evidence remains a separate collector. Its rows enrich the\n''',
    '''\tactorExit := services.ActorExitRecurrence{\n\t\tStatus: "not_investigated", EvidenceStatus: "not_investigated", ActorWallet: creator, Network: network, CurrentTarget: target,\n\t\tOtherTargets: []string{}, Signatures: []string{}, Slots: []int64{}, EventKinds: []string{}, Events: []services.ActorExitEventReference{}, Limitations: []string{},\n\t}\n\tif store != nil && creator != "" {\n\t\tif loaded, err := store.LoadActorExitRecurrence(ctx, creator, network, target); err == nil {\n\t\t\tactorExit = loaded\n\t\t\tcore.Analysis = services.ApplyActorExitRecurrenceToAnalysis(core.Analysis, loaded)\n\t\t\tcore.Bundle = services.EvidenceBackedSecurityRadarBundle(core.Analysis.Bundle)\n\t\t\tcore.Arms = services.ArvisArmsFromBundle(core.Bundle)\n\t\t\tif len(core.Arms) == 0 {\n\t\t\t\tcore.Arms = core.Analysis.Arms\n\t\t\t}\n\t\t\tcore.Final = services.ArvisFinalFromBundle(core.Bundle)\n\t\t} else {\n\t\t\tactorExit.Status = "unavailable"\n\t\t\tactorExit.EvidenceStatus = "unavailable"\n\t\t\tactorExit.Limitations = append(actorExit.Limitations, "Actor exit-event corpus query failed.")\n\t\t}\n\t}\n\n\t// Token-scoped live evidence remains a separate collector. Its rows enrich the\n''',
)
replace_once(
    'internal/handlers/unified_investigation_report.go',
    '''\tbehavior = services.ApplyCrossTokenFundingRecurrenceRuleV130(behavior, core.FundingRecurrence, now)\n''',
    '''\tbehavior = services.ApplyCrossTokenFundingRecurrenceRuleV130(behavior, core.FundingRecurrence, now)\n\tbehavior = services.ApplyCrossTokenExitEventRecurrenceRuleV140(behavior, actorExit, now)\n''',
)
replace_once(
    'internal/handlers/unified_investigation_report.go',
    '''\tunifiedVerdict := services.EvaluateUnifiedRadarVerdictV130(target, actorVerdict, behavior)\n''',
    '''\tunifiedVerdict := services.EvaluateUnifiedRadarVerdictV140(target, actorVerdict, behavior)\n''',
)
replace_once(
    'internal/handlers/unified_investigation_report.go',
    '''\t\t\t"token_lifecycle_recurrence": actorLifecycle,\n''',
    '''\t\t\t"token_lifecycle_recurrence": actorLifecycle,\n\t\t\t"exit_event_recurrence":        actorExit,\n''',
)
replace_once(
    'internal/handlers/unified_investigation_report.go',
    '''\t\t\t"funding_recurrence_can_change_grade":        false,\n''',
    '''\t\t\t"funding_recurrence_can_change_grade":        false,\n\t\t\t"exit_event_recurrence_can_change_grade":     false,\n''',
)

# Carry transaction refs from repeat_actor_scan into the existing track card row.
replace_once(
    'internal/handlers/unified_investigation_evidence_refs.go',
    '''for _, key := range []string{"signature", "transaction_signature", "source_signature", "creator_creation_signatures"} {''',
    '''for _, key := range []string{"signature", "transaction_signature", "source_signature", "creator_creation_signatures", "exit_event_signatures"} {''',
)
replace_once(
    'internal/handlers/unified_investigation_evidence_refs.go',
    '''\tfor _, slot := range signalInt64Values(arm.Signals["creator_creation_slots"]) {\n\t\tout.Slots = append(out.Slots, slot)\n\t}\n''',
    '''\tfor _, key := range []string{"creator_creation_slots", "exit_event_slots"} {\n\t\tfor _, slot := range signalInt64Values(arm.Signals[key]) {\n\t\t\tout.Slots = append(out.Slots, slot)\n\t\t}\n\t}\n''',
)
replace_once(
    'internal/handlers/unified_investigation_evidence_refs.go',
    '''for _, key := range []string{"owner_wallet", "creator_wallet", "wallet", "trader"} {''',
    '''for _, key := range []string{"owner_wallet", "creator_wallet", "wallet", "trader", "exit_event_actor_wallet"} {''',
)
replace_once(
    'internal/handlers/unified_investigation_evidence_refs.go',
    '''for _, key := range []string{"account", "account_address", "pool_address", "lp_mint", "token_vault", "quote_vault", "creator_other_mints"} {''',
    '''for _, key := range []string{"account", "account_address", "pool_address", "lp_mint", "token_vault", "quote_vault", "creator_other_mints", "exit_event_other_mints"} {''',
)

# Canonical immutable verdict projection understands v1.4 evidence-only C008.
replace_once(
    'internal/handlers/canonical_verdict_sync.go',
    '''\tif canonicalUnifiedRulesetAtLeast(behavior.RulesetVersion, 1, 3, 0) {\n\t\tfinal = services.EvaluateUnifiedRadarVerdictV130(target, actor, behavior)\n''',
    '''\tif canonicalUnifiedRulesetAtLeast(behavior.RulesetVersion, 1, 4, 0) {\n\t\tfinal = services.EvaluateUnifiedRadarVerdictV140(target, actor, behavior)\n\t} else if canonicalUnifiedRulesetAtLeast(behavior.RulesetVersion, 1, 3, 0) {\n\t\tfinal = services.EvaluateUnifiedRadarVerdictV130(target, actor, behavior)\n''',
)

# Owner-only deliberate warm-up endpoint; it queues canonical investigation jobs.
replace_once(
    'internal/http/server.go',
    '''\tmux.HandleFunc("/api/owner/radar/jobs", requiresDB(h, ownerOnly(h, method("POST", h.OwnerCreateCanonicalInvestigationJob))))\n''',
    '''\tmux.HandleFunc("/api/owner/radar/jobs", requiresDB(h, ownerOnly(h, method("POST", h.OwnerCreateCanonicalInvestigationJob))))\n\tmux.HandleFunc("/api/owner/radar/funding-corpus/warmup", requiresDB(h, ownerOnly(h, method("POST", h.OwnerWarmFundingCorpus))))\n''',
)
