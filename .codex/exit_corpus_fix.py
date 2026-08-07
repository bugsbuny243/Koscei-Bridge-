from pathlib import Path

ROOT = Path('koschei/api')

def replace_once(path, old, new):
    p = ROOT / path
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{path}: expected one match, got {count}')
    p.write_text(text.replace(old, new, 1))

replace_once(
    'internal/services/actor_defense_store.go',
    '''\titem.TokenMint = strings.TrimSpace(item.TokenMint)\n\titem.VerificationStatus = normalizeActorEvidenceStatus(item.VerificationStatus)\n''',
    '''\titem.TokenMint = strings.TrimSpace(item.TokenMint)\n\texitEventState, exitEventStateOK := strictActorExitEvidenceState(item.VerificationStatus)\n\titem.VerificationStatus = normalizeActorEvidenceStatus(item.VerificationStatus)\n''',
)
replace_once(
    'internal/services/actor_defense_store.go',
    '''\tif event, ok := actorExitEventFromEvidence(item); ok {\n\t\tif err := upsertActorExitEventTx(ctx, tx, event); err != nil {\n\t\t\treturn err\n\t\t}\n\t}\n''',
    '''\tif exitEventStateOK {\n\t\teventItem := item\n\t\teventItem.VerificationStatus = exitEventState\n\t\tif event, ok := actorExitEventFromEvidence(eventItem); ok {\n\t\t\tif err := upsertActorExitEventTx(ctx, tx, event); err != nil {\n\t\t\t\treturn err\n\t\t\t}\n\t\t}\n\t}\n''',
)
replace_once(
    'internal/services/actor_exit_events.go',
    '''func actorExitEventFromEvidence(item ActorDefenseEvidenceRecord) (ActorExitEvent, bool) {\n\tstate := normalizeActorEvidenceStatus(item.VerificationStatus)\n\tif state != "verified" && state != "observed" {\n\t\treturn ActorExitEvent{}, false\n\t}\n''',
    '''func strictActorExitEvidenceState(value string) (string, bool) {\n\tswitch strings.ToLower(strings.TrimSpace(value)) {\n\tcase "verified":\n\t\treturn "verified", true\n\tcase "observed":\n\t\treturn "observed", true\n\tdefault:\n\t\treturn "", false\n\t}\n}\n\nfunc actorExitEventFromEvidence(item ActorDefenseEvidenceRecord) (ActorExitEvent, bool) {\n\tstate, ok := strictActorExitEvidenceState(item.VerificationStatus)\n\tif !ok {\n\t\treturn ActorExitEvent{}, false\n\t}\n''',
)
replace_once(
    'internal/services/actor_exit_events_test.go',
    '''func TestActorExitEventFromCreatorSellIsWithheld(t *testing.T) {\n''',
    '''func TestActorExitEventFromEvidenceRejectsUnknownState(t *testing.T) {\n\titem := ActorDefenseEvidenceRecord{\n\t\tNetwork: "solana-mainnet", ActorWallet: "fixture-actor", TokenMint: "fixture-target",\n\t\tRelation: "dominant_holder_first_exit", VerificationStatus: "unexpected_status",\n\t\tSignature: "fixture-signature", Slot: 100, ObservedAt: time.Now().UTC(),\n\t\tMetadata: map[string]any{\n\t\t\t"unified_rule_id": UnifiedRuleDominantHolderFirstExit,\n\t\t\t"metrics": map[string]any{"holder_wallet": "fixture-holder"},\n\t\t},\n\t}\n\tif _, ok := actorExitEventFromEvidence(item); ok {\n\t\tt.Fatal("unknown evidence state was promoted to an exit-event observation")\n\t}\n}\n\nfunc TestActorExitEventFromCreatorSellIsWithheld(t *testing.T) {\n''',
)
