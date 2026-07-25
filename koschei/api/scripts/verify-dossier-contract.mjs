import { createHash } from 'node:crypto';
import { ACTOR_DOSSIER_ROW_IDS, DOSSIER_ROW_IDS, dossierCaseRef, verifyDossierObject } from '../../../oss/verifier/typescript/verify-dossier.mjs';

const hashBundle = body => ({
  ...body,
  bundle_hash: `sha256:${createHash('sha256').update(Buffer.from(JSON.stringify(body), 'utf8')).digest('hex')}`
});

const mint = 'Mint111';
const signature = 'VerdictSignature111';
const caseRef = dossierCaseRef(mint, signature);
const rows = DOSSIER_ROW_IDS.map(id => ({
  id,
  label: id,
  state: id === 'claim' || id === 'mev' ? 'not_applicable' : 'verified',
  value: { observed: true },
  refs: {
    wallets: id === 'concentration' ? ['Owner111'] : [],
    accounts: ['Mint111'],
    signatures: id === 'signed' ? [signature] : [],
    slots: id === 'launch' ? [100] : [],
    evidence_keys: [`row:${id}`]
  },
  limitations: []
}));

const tokenBody = {
  dossier_version: 'koschei-dossier-v1',
  case_ref: caseRef,
  produced_at: '2026-07-17T08:00:00Z',
  source_snapshot_hash: `sha256:${'a'.repeat(64)}`,
  target: { kind: 'token_mint', id: mint, network: 'solana-mainnet' },
  token: { mint, network: 'solana-mainnet' },
  verdict: { grade: 'F', signed: true, signature },
  verdict_card: { mapper_id: 'koschei-verdict-card', mapper_version: 'test', signal_rows: rows },
  threat_anticipation: { pathways: [] },
  evidence_arms: [],
  transaction_evidence: [],
  evidence_references: {},
  actor_dossier: {},
  holder_concentration_context: { available: true, sample_count: 50000 },
  technical_report: { target: mint },
  verification: { verdict_signature: signature, snapshot_identity: signature },
  limitations: ['Capability-not-intent', 'Identity boundary', 'Evidence-window boundary']
};
const bundle = hashBundle(tokenBody);
const valid = verifyDossierObject(bundle);
if (!valid.ok) throw new Error(`valid token dossier rejected: ${JSON.stringify(valid)}`);

const tampered = JSON.parse(JSON.stringify(bundle));
tampered.verdict.grade = 'A';
const invalid = verifyDossierObject(tampered);
if (invalid.ok || !invalid.errors.includes('bundle_hash_mismatch')) throw new Error(`tampered dossier accepted: ${JSON.stringify(invalid)}`);

const missingRefs = JSON.parse(JSON.stringify(bundle));
missingRefs.verdict_card.signal_rows.find(row => row.id === 'concentration').refs = { wallets: [], accounts: [], signatures: [], slots: [], evidence_keys: [] };
const missingResult = verifyDossierObject(missingRefs);
if (missingResult.ok || !missingResult.errors.includes('populated_signal_missing_refs:concentration')) throw new Error(`missing refs accepted: ${JSON.stringify(missingResult)}`);

const wallet = 'yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe';
const actorSignature = 'ActorUnifiedVerdict111';
const actorSnapshotIdentity = `actor-case:${'c'.repeat(64)}`;
const actorRows = ACTOR_DOSSIER_ROW_IDS.map((id, index) => ({
  id,
  label: `Actor acceptance ${index + 1}`,
  state: index === 8 ? 'not_verified' : index < 3 || index === 9 ? 'verified' : 'not_investigated',
  acceptance_status: index === 8 ? 'pass' : index < 3 || index === 9 ? 'pass' : 'not_investigated',
  value: { summary: index === 8 ? 'Direct creator → dominant-holder relation: NOT VERIFIED' : `Item ${index + 1}` },
  refs: index < 3 || index === 9 ? {
    wallets: [wallet], accounts: [], signatures: index === 2 ? ['CreateSig111'] : [], slots: index === 2 ? [101] : [], evidence_keys: [`actor:${id}`]
  } : { wallets: [], accounts: [], signatures: [], slots: [], evidence_keys: [] },
  limitations: index >= 3 && index !== 8 && index !== 9 ? ['Not investigated in bounded evidence.'] : []
}));
const actorBody = {
  dossier_version: 'koschei-dossier-v1',
  case_ref: dossierCaseRef(wallet, actorSnapshotIdentity),
  produced_at: '2026-07-17T08:00:00Z',
  source_snapshot_hash: `sha256:${'b'.repeat(64)}`,
  target: { kind: 'wallet', id: wallet, network: 'solana-mainnet', identity_scope: 'onchain_wallet_only' },
  verdict: { grade: 'D', signed: true, signature: actorSignature },
  verdict_card: { mapper_id: 'koschei-actor-acceptance-card', mapper_version: 'test', signal_rows: actorRows },
  actor_dossier: { wallet },
  actor_acceptance: { contract_version: 'koschei-actor-acceptance-v1', items: actorRows },
  created_token_history: [{ mint: 'Mint111', verification_status: 'verified' }],
  funding_origin: { status: 'not_investigated', verification_status: 'unverified' },
  cross_token_connections: { evidence_state: 'not_investigated', related_actor_observations: [] },
  evidence_log: [{ signature: 'CreateSig111', slot: 101, verification_status: 'verified' }],
  section_limitations: {
    acceptance_items: {}, funding_origin: ['Not investigated.'], created_token_history: [], cross_token_connections: [], evidence_log: []
  },
  technical_report: { target: wallet, analysis_scope: 'wallet_actor_investigation' },
  verification: { verdict_signature: actorSignature, snapshot_identity: actorSnapshotIdentity },
  limitations: ['Capability-not-intent', 'Identity boundary', 'Evidence-window boundary']
};
const actorBundle = hashBundle(actorBody);
const actorResult = verifyDossierObject(actorBundle);
if (!actorResult.ok) throw new Error(`valid actor dossier rejected: ${JSON.stringify(actorResult)}`);

const actorMissingStatus = JSON.parse(JSON.stringify(actorBundle));
delete actorMissingStatus.verdict_card.signal_rows[0].acceptance_status;
const actorMissingStatusResult = verifyDossierObject(actorMissingStatus);
if (actorMissingStatusResult.ok || !actorMissingStatusResult.errors.includes('actor_acceptance_status_invalid:AC-01')) {
  throw new Error(`actor acceptance status gap accepted: ${JSON.stringify(actorMissingStatusResult)}`);
}

console.log('dossier verifier contract: ok');
