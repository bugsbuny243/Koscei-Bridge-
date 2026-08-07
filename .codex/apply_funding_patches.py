from pathlib import Path

ROOT = Path("koschei/api")


def replace(path, old, new):
    p = ROOT / path
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, found {count}: {old[:80]!r}")
    p.write_text(text.replace(old, new, 1))

# Attach the funding corpus to the scan profile and persist/read it immediately
# after the existing holder-cluster analysis.
replace(
    "internal/services/security_radars.go",
    "\tHolderRoles                     HolderRoleAnalysis\n\tHolderCluster                   HolderClusterAnalysis\n\tTargetOldestBlockTime",
    "\tHolderRoles                     HolderRoleAnalysis\n\tHolderCluster                   HolderClusterAnalysis\n\tFundingRecurrence               FundingRecurrenceAnalysis\n\tTargetOldestBlockTime",
)
replace(
    "internal/services/security_radars.go",
    "\tif profile.IsTokenMint && profile.HolderRoles.Available {\n\t\tprofile.HolderCluster = AnalyzeSolanaHolderCluster(ctx, rpcURL, req.Target, profile.HolderRoles, profile.TargetOldestBlockTime, profile.TargetOldestSlot)\n\t}\n",
    "\tif profile.IsTokenMint && profile.HolderRoles.Available {\n\t\tprofile.HolderCluster = AnalyzeSolanaHolderCluster(ctx, rpcURL, req.Target, profile.HolderRoles, profile.TargetOldestBlockTime, profile.TargetOldestSlot)\n\t\tif store := securityRadarStoreFromContext(ctx); store != nil {\n\t\t\t_ = store.CaptureFundingClusters(ctx, req.Target, req.Network, profile.HolderCluster)\n\t\t\tif recurrence, err := store.LoadFundingRecurrence(ctx, req.Target, req.Network, profile.HolderCluster); err == nil {\n\t\t\t\tprofile.FundingRecurrence = recurrence\n\t\t\t} else {\n\t\t\t\tprofile.FundingRecurrence = FundingRecurrenceAnalysis{\n\t\t\t\t\tStatus: \"unavailable\", EvidenceStatus: \"unavailable\", CurrentTarget: req.Target, Network: normalizeRadarNetwork(req.Network),\n\t\t\t\t\tSources: []FundingSourceRecurrence{}, Limitations: []string{\"Funding corpus read failed after holder-cluster persistence.\"},\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n",
)

# Keep recurrence in ARVIS metadata and funding-arm lineage.
replace(
    "internal/services/arvis_arms.go",
    "\t\t\t\"holder_cluster_analysis\": profile.HolderCluster,\n",
    "\t\t\t\"holder_cluster_analysis\": profile.HolderCluster,\n\t\t\t\"funding_recurrence\":       profile.FundingRecurrence,\n",
)
replace(
    "internal/services/arvis_arms.go",
    "\t\tv.Signals[\"cluster_confidence\"] = a.Confidence\n",
    "\t\tv.Signals[\"cluster_confidence\"] = a.Confidence\n\t\tv.Signals[\"funding_recurrence\"] = p.FundingRecurrence\n",
)
replace(
    "internal/services/arvis_arms.go",
    "\ts[\"cluster_confidence\"] = a.Confidence\n\ts[\"shared_funding_group_count\"] = a.SharedFundingGroupCount\n",
    "\ts[\"cluster_confidence\"] = a.Confidence\n\ts[\"funding_recurrence\"] = p.FundingRecurrence\n\ts[\"shared_funding_group_count\"] = a.SharedFundingGroupCount\n",
)
replace(
    "internal/services/arvis_arms.go",
    "\te := append([]string{}, a.Findings...)\n\tfor _, limitation := range a.Limitations {\n",
    "\te := append([]string{}, a.Findings...)\n\tfor _, recurrence := range p.FundingRecurrence.Sources {\n\t\tif recurrence.DistinctTargets >= UnifiedFundingRecurrenceMinimumTargetCount && recurrence.ReferencesComplete {\n\t\t\te = append(e, fmt.Sprintf(\"Cross-token funding recurrence: funder %s also appears on token mint(s): %s.\", recurrence.FundingSource, strings.Join(recurrence.OtherTargets, \", \\")))\n\t\t}\n\t}\n\tfor _, limitation := range a.Limitations {\n",
)

# Give the scan an existing request-scoped DB store; no new pool or worker.
replace(
    "internal/handlers/holder_intelligence_core.go",
    "\tRepeatDominantHolders []services.RepeatDominantHolderEvidence\n\tThreatAnticipation",
    "\tRepeatDominantHolders []services.RepeatDominantHolderEvidence\n\tFundingRecurrence     services.FundingRecurrenceAnalysis\n\tThreatAnticipation",
)
replace(
    "internal/handlers/holder_intelligence_core.go",
    "\treq := services.SecurityRadarRequest{Target: target, Network: network, Mode: mode}\n\tanalysis := services.AnalyzeArvisRadarsContext(parent, req)\n",
    "\treq := services.SecurityRadarRequest{Target: target, Network: network, Mode: mode}\n\tanalysisCtx := parent\n\tif h != nil {\n\t\thistoryDB := h.DB\n\t\tif historyDB == nil {\n\t\t\thistoryDB = h.DBRead\n\t\t}\n\t\tif historyDB != nil {\n\t\t\tanalysisCtx = services.WithSecurityRadarStore(parent, services.NewSecurityRadarStore(historyDB))\n\t\t}\n\t}\n\tanalysis := services.AnalyzeArvisRadarsContext(analysisCtx, req)\n",
)
replace(
    "internal/handlers/holder_intelligence_core.go",
    "\tcluster := services.ArvisHolderClusterFromBundle(bundle)\n",
    "\tcluster := services.ArvisHolderClusterFromBundle(bundle)\n\tfundingRecurrence := services.ArvisFundingRecurrenceFromBundle(bundle)\n",
)
replace(
    "internal/handlers/holder_intelligence_core.go",
    "RepeatDominantHolders: repeatDominant, ThreatAnticipation:",
    "RepeatDominantHolders: repeatDominant, FundingRecurrence: fundingRecurrence, ThreatAnticipation:",
)

# Read lifecycle memory into Repeat Actor Scan before report modules/refs are built.
replace(
    "internal/handlers/unified_investigation_report.go",
    "\t// Token-scoped live evidence remains a separate collector. Its rows enrich the\n",
    "\tactorLifecycle := services.ActorTokenLifecycleRecurrence{\n\t\tStatus: \"not_investigated\", EvidenceStatus: \"not_investigated\", ActorWallet: creator, Network: network, CurrentMint: target,\n\t\tOtherMints: []string{}, CreationSignatures: []string{}, CreationSlots: []int64{}, RuggedStatus: \"not_classified_by_lifecycle_table\", Limitations: []string{},\n\t}\n\tif store != nil && creator != \"\" {\n\t\tif loaded, err := store.LoadTokenLifecycleRecurrence(ctx, creator, network, target); err == nil {\n\t\t\tactorLifecycle = loaded\n\t\t\tcore.Analysis = services.ApplyActorTokenLifecycleRecurrenceToAnalysis(core.Analysis, loaded)\n\t\t\tcore.Bundle = services.EvidenceBackedSecurityRadarBundle(core.Analysis.Bundle)\n\t\t\tcore.Arms = services.ArvisArmsFromBundle(core.Bundle)\n\t\t\tif len(core.Arms) == 0 {\n\t\t\t\tcore.Arms = core.Analysis.Arms\n\t\t\t}\n\t\t\tcore.Final = services.ArvisFinalFromBundle(core.Bundle)\n\t\t} else {\n\t\t\tactorLifecycle.Status = \"unavailable\"\n\t\t\tactorLifecycle.EvidenceStatus = \"unavailable\"\n\t\t\tactorLifecycle.Limitations = append(actorLifecycle.Limitations, \"Actor lifecycle corpus query failed.\")\n\t\t}\n\t}\n\n\t// Token-scoped live evidence remains a separate collector. Its rows enrich the\n",
)
replace(
    "internal/handlers/unified_investigation_report.go",
    "\tbehavior = services.ApplyOwnerConcentrationRuleV110(behavior, core.Intelligence, now)\n",
    "\tbehavior = services.ApplyOwnerConcentrationRuleV110(behavior, core.Intelligence, now)\n\tbehavior = services.ApplyCrossTokenFundingRecurrenceRuleV130(behavior, core.FundingRecurrence, now)\n",
)
replace(
    "internal/handlers/unified_investigation_report.go",
    "\tunifiedVerdict := services.EvaluateUnifiedRadarVerdictV110(target, actorVerdict, behavior)\n",
    "\tunifiedVerdict := services.EvaluateUnifiedRadarVerdictV130(target, actorVerdict, behavior)\n",
)
replace(
    "internal/handlers/unified_investigation_report.go",
    "\t\t\t\"current_token_distribution\": distributionRun,\n",
    "\t\t\t\"current_token_distribution\": distributionRun,\n\t\t\t\"token_lifecycle_recurrence\": actorLifecycle,\n",
)
replace(
    "internal/handlers/unified_investigation_report.go",
    "\t\t\t\"verified_actor_evidence_can_change_verdict\": true,\n",
    "\t\t\t\"verified_actor_evidence_can_change_verdict\": true,\n\t\t\t\"funding_recurrence_can_change_grade\":       false,\n",
)

# Add explicit dossier refs: funding source + other mint(s), and lifecycle refs.
replace(
    "internal/handlers/unified_investigation_evidence_refs.go",
    "\trefs[\"funding\"] = mergeUnifiedEvidenceReferences(refs[\"funding\"], creatorRef)\n",
    "\tfundingRecurrenceRef := unifiedEvidenceReference{}\n\tfor _, recurrence := range core.FundingRecurrence.Sources {\n\t\tif recurrence.DistinctTargets < services.UnifiedFundingRecurrenceMinimumTargetCount || !recurrence.ReferencesComplete {\n\t\t\tcontinue\n\t\t}\n\t\tfundingRecurrenceRef.Wallets = append(fundingRecurrenceRef.Wallets, recurrence.FundingSource)\n\t\tfundingRecurrenceRef.Accounts = append(fundingRecurrenceRef.Accounts, recurrence.OtherTargets...)\n\t}\n\trefs[\"funding\"] = mergeUnifiedEvidenceReferences(refs[\"funding\"], creatorRef, fundingRecurrenceRef)\n",
)
replace(
    "internal/handlers/unified_investigation_evidence_refs.go",
    "\tfor _, key := range []string{\"signature\", \"transaction_signature\", \"source_signature\"} {\n",
    "\tfor _, key := range []string{\"signature\", \"transaction_signature\", \"source_signature\", \"creator_creation_signatures\"} {\n",
)
replace(
    "internal/handlers/unified_investigation_evidence_refs.go",
    "\tfor _, key := range []string{\"account\", \"account_address\", \"pool_address\", \"lp_mint\", \"token_vault\", \"quote_vault\"} {\n",
    "\tfor _, key := range []string{\"account\", \"account_address\", \"pool_address\", \"lp_mint\", \"token_vault\", \"quote_vault\", \"creator_other_mints\"} {\n",
)
replace(
    "internal/handlers/unified_investigation_evidence_refs.go",
    "\tfor _, key := range []string{\"slot\", \"read_slot\", \"context_slot\", \"launch_slot\"} {\n\t\tif slot := signalInt64(arm.Signals[key]); slot > 0 {\n\t\t\tout.Slots = append(out.Slots, slot)\n\t\t}\n\t}\n",
    "\tfor _, key := range []string{\"slot\", \"read_slot\", \"context_slot\", \"launch_slot\"} {\n\t\tif slot := signalInt64(arm.Signals[key]); slot > 0 {\n\t\t\tout.Slots = append(out.Slots, slot)\n\t\t}\n\t}\n\tfor _, slot := range signalInt64Values(arm.Signals[\"creator_creation_slots\"]) {\n\t\tout.Slots = append(out.Slots, slot)\n\t}\n",
)
replace(
    "internal/handlers/unified_investigation_evidence_refs.go",
    "func signalInt64(value any) int64 {\n",
    "func signalInt64Values(value any) []int64 {\n\tout := []int64{}\n\tswitch typed := value.(type) {\n\tcase []int64:\n\t\treturn append(out, typed...)\n\tcase []any:\n\t\tfor _, item := range typed {\n\t\t\tif slot := signalInt64(item); slot > 0 {\n\t\t\t\tout = append(out, slot)\n\t\t\t}\n\t\t}\n\t}\n\treturn out\n}\n\nfunc signalInt64(value any) int64 {\n",
)

# V1.3 is accepted by canonical verdict synchronization.
replace(
    "internal/handlers/canonical_verdict_sync.go",
    "\tif canonicalUnifiedRulesetAtLeast(behavior.RulesetVersion, 1, 2, 0) {\n\t\tfinal = services.EvaluateUnifiedRadarVerdictV120(target, actor, behavior)\n\t} else {\n",
    "\tif canonicalUnifiedRulesetAtLeast(behavior.RulesetVersion, 1, 3, 0) {\n\t\tfinal = services.EvaluateUnifiedRadarVerdictV130(target, actor, behavior)\n\t} else if canonicalUnifiedRulesetAtLeast(behavior.RulesetVersion, 1, 2, 0) {\n\t\tfinal = services.EvaluateUnifiedRadarVerdictV120(target, actor, behavior)\n\t} else {\n",
)

# Metadata impersonation deliberately stays unfed until a real detector exists.
replace(
    "internal/handlers/dossier_signal_registry.go",
    "\t{ID: \"metadata\", Label: \"Metadata scam / impersonation\", Source: signalSource{Kind: signalSourceReport, Key: \"metadata_impersonation\"}, RequireRefs: true},\n",
    "\t// metadata_impersonation intentionally has no detector yet. Until Koschei has a\n\t// verifiable metadata-identity source, this row remains not_investigated rather\n\t// than borrowing an unrelated module or inventing an observed state.\n\t{ID: \"metadata\", Label: \"Metadata scam / impersonation\", Source: signalSource{Kind: signalSourceReport, Key: \"metadata_impersonation\"}, RequireRefs: true},\n",
)
replace(
    "internal/handlers/dossier_signal_registry_test.go",
    "func TestBuildDossierSignalRowsRendersWholeRegistry(t *testing.T) {\n",
    "func TestMetadataImpersonationIntentionallyRemainsNotInvestigated(t *testing.T) {\n\tdef, ok := signalDefinitionByID(\"metadata\")\n\tif !ok {\n\t\tt.Fatal(\"metadata registry row missing\")\n\t}\n\t// No verifiable metadata-impersonation detector exists yet. The deliberate\n\t// contract is not_investigated, never an inferred or observed substitute.\n\tstate, _ := signalStateFor(dossierChangeFixture(), def)\n\tif state != signalStateNotInvestigated {\n\t\tt.Fatalf(\"metadata state=%q want=%q\", state, signalStateNotInvestigated)\n\t}\n}\n\nfunc TestBuildDossierSignalRowsRendersWholeRegistry(t *testing.T) {\n",
)

print("funding/lifecycle patch set applied")
