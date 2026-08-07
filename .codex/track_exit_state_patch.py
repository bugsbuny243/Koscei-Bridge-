from pathlib import Path

ROOT = Path('koschei/api')

def replace_once(path, old, new):
    p = ROOT / path
    text = p.read_text()
    if text.count(old) != 1:
        raise SystemExit(f'{path}: expected one match, got {text.count(old)}')
    p.write_text(text.replace(old, new, 1))

replace_once(
    'internal/services/actor_exit_events.go',
    '''\t\tif recurrence.DistinctTargetsWithEvents >= 2 && recurrence.ReferencesComplete {\n\t\t\tarms[index].Signals["finding_observed"] = true\n''',
    '''\t\tif recurrence.DistinctTargetsWithEvents >= 2 && recurrence.ReferencesComplete {\n\t\t\tarms[index].Signals["execution_status"] = recurrence.EvidenceStatus\n\t\t\tarms[index].Signals["finding_observed"] = true\n''',
)
replace_once(
    'internal/handlers/dossier_track_exit_events_test.go',
    '''\t\t\t\t"signed":          true,\n\t\t\t\t"signature":       "fixture-arm-signature",\n\t\t\t\t"evidence_status": "verified",\n\t\t\t\t"signals": map[string]any{\n\t\t\t\t\t"cross_token_exit_event_recurrence": true,\n''',
    '''\t\t\t\t"signals": map[string]any{\n\t\t\t\t\t"execution_status":                   "verified",\n\t\t\t\t\t"cross_token_exit_event_recurrence": true,\n''',
)
