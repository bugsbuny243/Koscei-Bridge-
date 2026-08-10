package services

const (
	ArvisCapabilityStrong       = "strong_evidence_arm"
	ArvisCapabilityPartial      = "partial_evidence_path"
	ArvisCapabilityPlanned      = "planned_evidence_path"
	ArvisCapabilitySchemaOnly   = "schema_only"
	ArvisCapabilityUnavailable  = "not_a_verified_claim"
	ArvisCapabilityRulesetScope = "actor-v1.0/unified-radar-v1.0"
)

type ArvisInvestigationCapability struct {
	ID                    string   `json:"id"`
	Label                 string   `json:"label"`
	Status                string   `json:"status"`
	TargetStatus          string   `json:"target_status"`
	PrimaryModules        []string `json:"primary_modules,omitempty"`
	CanonicalSections     []string `json:"canonical_sections"`
	ActorRulesetVersion   string   `json:"actor_ruleset_version"`
	UnifiedRulesetVersion string   `json:"unified_radar_ruleset_version"`
	EvidencePolicy        string   `json:"evidence_policy"`
	NextEvidenceNeed      string   `json:"next_evidence_need,omitempty"`
	MaxStrengthGate       []string `json:"max_strength_gate"`
}

func ArvisInvestigationCapabilities() []ArvisInvestigationCapability {
	capabilities := []ArvisInvestigationCapability{
		{
			ID: "solana_token_intelligence", Label: "Solana token intelligence", Status: ArvisCapabilityStrong,
			PrimaryModules:      []string{ModuleTokenAuthorityScanner, ModuleHolderConcentration, ModuleProgramRelationScan},
			CanonicalSections:   []string{"ACTOR_INVESTIGATION_ENGINE.md#1", "ACTOR_INVESTIGATION_ENGINE.md#2", "ACTOR_INVESTIGATION_ENGINE.md#4"},
			ActorRulesetVersion: ActorDefenseRulesetVersion, UnifiedRulesetVersion: UnifiedRadarRulesetVersion,
			EvidencePolicy: "Token authority, holder concentration and program relation evidence may be signed only when backed by parsed Solana RPC observations.",
		},
		{
			ID: "holder_funding_sybil", Label: "Holder / funding / sybil", Status: ArvisCapabilityStrong,
			PrimaryModules:      []string{ModuleHolderConcentration, ModuleFundingClusterDetector, ModulePumpSybilRadar, ModuleSniperTimingDetector},
			CanonicalSections:   []string{"ACTOR_INVESTIGATION_ENGINE.md#1", "ACTOR_INVESTIGATION_ENGINE.md#3", "ACTOR_INVESTIGATION_ENGINE.md#4"},
			ActorRulesetVersion: ActorDefenseRulesetVersion, UnifiedRulesetVersion: UnifiedRadarRulesetVersion,
			EvidencePolicy: "Funding and sybil relations remain evidence rows or watch flags; timing coordination alone is not common ownership.",
		},
		{
			ID: "creator_repeat_actor_memory", Label: "Creator / repeat actor memory", Status: ArvisCapabilityPartial,
			PrimaryModules:      []string{ModuleCreatorLinkAnalysis, ModuleRepeatActorScan},
			CanonicalSections:   []string{"ACTOR_INVESTIGATION_ENGINE.md#1", "ACTOR_INVESTIGATION_ENGINE.md#2", "ACTOR_INVESTIGATION_ENGINE.md#6"},
			ActorRulesetVersion: ActorDefenseRulesetVersion, UnifiedRulesetVersion: UnifiedRadarRulesetVersion,
			EvidencePolicy:   "Creator, dominant-holder and repeat-actor context is persisted in retention-independent actor memory; exact-address incident recurrence can be VERIFIED only from immutable signature/slot-backed corpus records.",
			NextEvidenceNeed: "Increase verified creator/deployer and exit-event coverage so more actors qualify for immutable incident and campaign-genome memory without broad recipient wallet-history scans.",
		},
		{
			ID: "incident_behavior_memory", Label: "Verified incident / behavioral memory", Status: ArvisCapabilityPartial,
			PrimaryModules:      []string{ModuleRepeatActorScan, ModuleFundingClusterDetector, ModuleIntelligenceGraph},
			CanonicalSections:   []string{"ACTOR_INVESTIGATION_ENGINE.md#3", "ACTOR_INVESTIGATION_ENGINE.md#6"},
			ActorRulesetVersion: ActorDefenseRulesetVersion, UnifiedRulesetVersion: UnifiedRadarRulesetVersion,
			EvidencePolicy:   "Immutable incident rows require a VERIFIED actor event with signature+slot and a Koschei-signed material final token verdict. Campaign-genome matches across wallet addresses remain technical-pattern watch signals and never identity claims.",
			NextEvidenceNeed: "Measure precision and recurrence support for versioned KOSCH-BEH behavior families before any family becomes eligible to influence a deterministic customer grade.",
		},
		{
			ID: "launch_sniper_intelligence", Label: "Launch / sniper intelligence", Status: ArvisCapabilityStrong,
			PrimaryModules:      []string{ModuleLaunchDistribution, ModuleSniperTimingDetector},
			CanonicalSections:   []string{"ACTOR_INVESTIGATION_ENGINE.md#1", "ACTOR_INVESTIGATION_ENGINE.md#2", "ACTOR_INVESTIGATION_ENGINE.md#4"},
			ActorRulesetVersion: ActorDefenseRulesetVersion, UnifiedRulesetVersion: UnifiedRadarRulesetVersion,
			EvidencePolicy: "Launch distribution must stay mint-specific/ATA-based; synchronized launch timing is evidence, not identity attribution.",
		},
		{
			ID: "liquidity_drain_attribution", Label: "Liquidity drain attribution", Status: ArvisCapabilityPartial,
			PrimaryModules:      []string{ModuleLiquidityMovement, ModuleRaydiumPoolGuardian},
			CanonicalSections:   []string{"ACTOR_INVESTIGATION_ENGINE.md#1", "ACTOR_INVESTIGATION_ENGINE.md#2", "ACTOR_INVESTIGATION_ENGINE.md#5"},
			ActorRulesetVersion: ActorDefenseRulesetVersion, UnifiedRulesetVersion: UnifiedRadarRulesetVersion,
			EvidencePolicy:   "Liquidity drain attribution requires parsed add/remove transactions, actor linkage and signed evidence rows before any hard trigger is eligible.",
			NextEvidenceNeed: "Connect pool reserve deltas, LP authority and creator/dominant-holder actor relations to the Liquidity Movement arm.",
		},
		{
			ID: "transaction_intent", Label: "Transaction intent", Status: ArvisCapabilityStrong,
			PrimaryModules:      []string{ModuleProgramRelationScan, ModuleClaimSurfaceRisk, ModuleWalletlessClaimShield},
			CanonicalSections:   []string{"ACTOR_INVESTIGATION_ENGINE.md#1", "ACTOR_INVESTIGATION_ENGINE.md#2", "ACTOR_INVESTIGATION_ENGINE.md#4"},
			ActorRulesetVersion: ActorDefenseRulesetVersion, UnifiedRulesetVersion: UnifiedRadarRulesetVersion,
			EvidencePolicy:   "Intent must be derived from parsed instruction, signer, writable account and token/SOL delta evidence, not natural-language guesses.",
			NextEvidenceNeed: "Extend the parsed transaction intent object with route-specific claim, swap and approval semantics while preserving the 14-arm contract.",
		},
		{
			ID: "mev_sandwich", Label: "MEV / sandwich", Status: ArvisCapabilityPartial,
			PrimaryModules:      []string{ModuleMEVShield},
			CanonicalSections:   []string{"ACTOR_INVESTIGATION_ENGINE.md#3", "ACTOR_INVESTIGATION_ENGINE.md#4", "ACTOR_INVESTIGATION_ENGINE.md#5"},
			ActorRulesetVersion: ActorDefenseRulesetVersion, UnifiedRulesetVersion: UnifiedRadarRulesetVersion,
			EvidencePolicy:   "Priority, bundle or route exposure can be reported; confirmed sandwich claims require swap, slippage and before/after route evidence.",
			NextEvidenceNeed: "Attach route, slippage and pool-state before/after observations to MEV Shield.",
		},
		{
			ID: "market_manipulation", Label: "Market manipulation", Status: ArvisCapabilityPlanned,
			PrimaryModules:      []string{ModuleFundingClusterDetector, ModuleLiquidityMovement, ModuleHolderConcentration},
			CanonicalSections:   []string{"ACTOR_INVESTIGATION_ENGINE.md#3", "ACTOR_INVESTIGATION_ENGINE.md#5"},
			ActorRulesetVersion: ActorDefenseRulesetVersion, UnifiedRulesetVersion: UnifiedRadarRulesetVersion,
			EvidencePolicy:   "Manipulation labels are not verified claims until deterministic behavior rules cite transaction-backed evidence rows.",
			NextEvidenceNeed: "Map wash/self-flow, coordinated exits and volume/liquidity gaps into versioned deterministic behavior rules.",
		},
		{
			ID: "watch_intelligence", Label: "Watch intelligence", Status: ArvisCapabilityPartial,
			PrimaryModules:      []string{ModuleIntelligenceGraph, ModuleRepeatActorScan},
			CanonicalSections:   []string{"ACTOR_INVESTIGATION_ENGINE.md#3", "ACTOR_INVESTIGATION_ENGINE.md#6"},
			ActorRulesetVersion: ActorDefenseRulesetVersion, UnifiedRulesetVersion: UnifiedRadarRulesetVersion,
			EvidencePolicy:   "Watch intelligence may surface operational overlap, funding-outcome recurrence and cross-wallet campaign-genome similarity; these signals remain separate from grade-affecting verified rules.",
			NextEvidenceNeed: "Accumulate enough immutable incident and genome snapshots to measure watch-signal precision, false-positive rate and recurrence support by behavior family.",
		},
		{
			ID: "cross_chain_intelligence", Label: "Cross-chain intelligence", Status: ArvisCapabilitySchemaOnly,
			CanonicalSections:   []string{"ACTOR_INVESTIGATION_ENGINE.md#3", "ACTOR_INVESTIGATION_ENGINE.md#4", "ACTOR_INVESTIGATION_ENGINE.md#6"},
			ActorRulesetVersion: ActorDefenseRulesetVersion, UnifiedRulesetVersion: UnifiedRadarRulesetVersion,
			EvidencePolicy:   "Bridge, chain-hopping, mixer, peel-chain, stablecoin-conversion and CEX/OTC movement claims remain unavailable until verified cross-chain evidence rows exist.",
			NextEvidenceNeed: "Add verified bridge/chain evidence ingestion before surfacing cross-chain criminal-pattern claims.",
		},
		{
			ID: "unverified_cross_chain_crime_patterns", Label: "Cross-chain criminal patterns", Status: ArvisCapabilityUnavailable,
			CanonicalSections:   []string{"ACTOR_INVESTIGATION_ENGINE.md#3", "ACTOR_INVESTIGATION_ENGINE.md#4"},
			ActorRulesetVersion: ActorDefenseRulesetVersion, UnifiedRulesetVersion: UnifiedRadarRulesetVersion,
			EvidencePolicy:   "No mixer, peel-chain, bridge-laundering, OTC or Solana-to-EVM same-actor assertion may be emitted as verified production output without signature-level evidence rows.",
			NextEvidenceNeed: "Define bridge, mixer, peel-chain and stablecoin conversion evidence-row schemas before any production verdict integration.",
		},
	}
	for i := range capabilities {
		capabilities[i].TargetStatus = ArvisCapabilityStrong
		capabilities[i].MaxStrengthGate = arvisCapabilityMaxStrengthGate(capabilities[i].ID)
	}
	return capabilities
}

func arvisCapabilityMaxStrengthGate(id string) []string {
	common := []string{
		"Preserve the 14-arm ARVIS contract and deterministic unified Radar verdict ownership.",
		"Attach only VERIFIED or OBSERVED evidence to claims; keep INFERRED evidence watch-only and UNVERIFIED evidence out of verified claims.",
		"Carry signature, slot, timestamp, source, destination, amount, program and verification status for serious claims.",
	}
	specific := map[string][]string{
		"solana_token_intelligence": {
			"Parse mint, authority, freeze, supply, holder and program evidence from live Solana RPC or signed transaction evidence.",
			"Keep token capability findings evidence-only until unified deterministic rules evaluate them.",
		},
		"holder_funding_sybil": {
			"Resolve holder roles and mint-specific token accounts before interpreting holder concentration.",
			"Require direct funding signatures or repeated OBSERVED cluster evidence before linking wallets beyond watch flags.",
		},
		"creator_repeat_actor_memory": {
			"Persist creator, deployer, dominant-holder and recipient roles in durable actor-index rows.",
			"Prove cross-token reuse with immutable incident references or exact stored evidence keys and signatures, not broad recipient wallet-history scans.",
		},
		"incident_behavior_memory": {
			"Materialize only VERIFIED signature+slot actor events joined to signed material final token verdicts in the immutable incident corpus.",
			"Keep cross-wallet campaign-genome and operational-overlap matches watch-only until independently verified evidence supports any stronger rule.",
			"Version behavior families and measure precision before allowing any family to affect the unified deterministic verdict.",
		},
		"launch_sniper_intelligence": {
			"Use mint-specific ATA and launch ledger evidence for initial recipient analysis.",
			"Separate synchronized timing evidence from common-ownership attribution unless direct links exist.",
		},
		"liquidity_drain_attribution": {
			"Attach parsed liquidity add/remove signatures, pool reserve deltas, LP authority and actor linkage.",
			"Trigger creator liquidity-removal hard rules only from VERIFIED transaction-backed evidence.",
		},
		"transaction_intent": {
			"Classify intent from parsed instructions, signer set, writable accounts, program IDs and token/SOL balance deltas.",
			"Extend route-specific claim, swap, approval, close-account, mint, burn and transfer semantics without issuing a grade.",
		},
		"mev_sandwich": {
			"Attach route, slippage, priority fee, bundle, pool-state before/after and affected swap evidence.",
			"Report confirmed sandwich claims only when before/after route evidence is VERIFIED.",
		},
		"market_manipulation": {
			"Map wash/self-flow, coordinated exits, volume/liquidity gaps and holder pressure into versioned deterministic behavior rules.",
			"Never label manipulation from a single inferred pattern without transaction-backed evidence rows.",
		},
		"watch_intelligence": {
			"Use immutable actor/incident/genome memory while preserving opt-in live collection and provider quotas.",
			"Keep operational overlap, funding outcome and cross-wallet genome similarity separate from grade-affecting verified rules.",
		},
		"cross_chain_intelligence": {
			"Add verified bridge, source-chain, destination-chain, stablecoin conversion and exchange/OTC evidence ingestion.",
			"Require chain-specific transaction evidence before linking Solana and non-Solana actors.",
		},
		"unverified_cross_chain_crime_patterns": {
			"Define mixer entry/exit, peel-chain, bridge-laundering and CEX/OTC movement evidence-row schemas.",
			"Promote criminal-pattern claims only after verified signatures prove the path; otherwise keep them unavailable.",
		},
	}
	return append(common, specific[id]...)
}
