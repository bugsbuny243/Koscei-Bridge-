package finalgate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

type finalSecurityManifest struct {
	SchemaVersion          string                   `json:"schema_version"`
	BaselineName           string                   `json:"baseline_name"`
	ReleaseClass           string                   `json:"release_class"`
	ProductionGAClaim      bool                     `json:"production_ga_claim"`
	ProductionLatencyClaim bool                     `json:"production_latency_claim"`
	Policy                 finalSecurityPolicy      `json:"policy"`
	Invariants             []finalSecurityInvariant `json:"invariants"`
}

type finalSecurityPolicy struct {
	AllInvariantsReleaseBlocking           bool `json:"all_invariants_release_blocking"`
	ReferencedTestsMustExist               bool `json:"referenced_tests_must_exist"`
	ReferencedTestsRunUnderGoTestAll       bool `json:"referenced_tests_run_under_go_test_all"`
	NoTestPresenceOnlySubstituteExecution  bool `json:"no_test_presence_only_substitute_for_execution"`
	NoRealWorldIdentityClaim               bool `json:"no_real_world_identity_claim"`
	NoAIVerdictAuthority                   bool `json:"no_ai_verdict_authority"`
	NoCustodyOrTransactionSubmission       bool `json:"no_custody_or_transaction_submission"`
}

type finalSecurityInvariant struct {
	ID      string `json:"id"`
	Domain  string `json:"domain"`
	Package string `json:"package"`
	Test    string `json:"test"`
	Claim   string `json:"claim"`
}

func TestFinalSecurityInvariantManifestReferencesExecutableTests(t *testing.T) {
	root := finalGateAPIRoot(t)
	manifestPath := filepath.Join(root, "final_security_invariants.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var manifest finalSecurityManifest
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatalf("decode final security manifest: %v", err)
	}

	if manifest.SchemaVersion != "koschei-final-security-invariants-v1" {
		t.Fatalf("schema_version=%q", manifest.SchemaVersion)
	}
	if strings.TrimSpace(manifest.BaselineName) == "" || manifest.ReleaseClass != "code_feature_complete_candidate" {
		t.Fatalf("invalid baseline metadata: %#v", manifest)
	}
	if manifest.ProductionGAClaim || manifest.ProductionLatencyClaim {
		t.Fatal("final code invariant manifest must not fabricate production GA or latency evidence")
	}
	if !manifest.Policy.AllInvariantsReleaseBlocking || !manifest.Policy.ReferencedTestsMustExist || !manifest.Policy.ReferencedTestsRunUnderGoTestAll || !manifest.Policy.NoTestPresenceOnlySubstituteExecution {
		t.Fatalf("release-blocking execution policy weakened: %#v", manifest.Policy)
	}
	if !manifest.Policy.NoRealWorldIdentityClaim || !manifest.Policy.NoAIVerdictAuthority || !manifest.Policy.NoCustodyOrTransactionSubmission {
		t.Fatalf("security constitution weakened: %#v", manifest.Policy)
	}
	if len(manifest.Invariants) < 14 {
		t.Fatalf("invariant count=%d want>=14", len(manifest.Invariants))
	}

	requiredIDs := map[string]bool{
		"state_witness_order_determinism":                    false,
		"state_witness_state_sensitivity":                    false,
		"state_recheck_rejects_untrusted_permit_before_rpc": false,
		"state_recheck_safe_to_proceed_fail_closed":         false,
		"evidence_court_primary_identity_excluded":          false,
		"permit_v3_semantic_policy_consistency":             false,
		"transaction_value_evidence_determinism":            false,
		"program_trust_transaction_network_binding":         false,
		"program_trust_verdict_authority_isolation":         false,
		"campaign_genome_cross_wallet_pattern_determinism":  false,
		"campaign_genome_watch_and_unverified_boundary":     false,
	}
	seenIDs := map[string]struct{}{}
	seenTargets := map[string]struct{}{}
	packageTests := map[string]map[string]struct{}{}
	for _, invariant := range manifest.Invariants {
		invariant.ID = strings.TrimSpace(invariant.ID)
		invariant.Domain = strings.TrimSpace(invariant.Domain)
		invariant.Package = strings.TrimSpace(invariant.Package)
		invariant.Test = strings.TrimSpace(invariant.Test)
		invariant.Claim = strings.TrimSpace(invariant.Claim)
		if invariant.ID == "" || invariant.Domain == "" || invariant.Package == "" || invariant.Test == "" || invariant.Claim == "" {
			t.Fatalf("incomplete invariant: %#v", invariant)
		}
		if !strings.HasPrefix(invariant.Package, "./internal/") || !strings.HasPrefix(invariant.Test, "Test") {
			t.Fatalf("unsafe invariant target: %#v", invariant)
		}
		if _, exists := seenIDs[invariant.ID]; exists {
			t.Fatalf("duplicate invariant id %q", invariant.ID)
		}
		seenIDs[invariant.ID] = struct{}{}
		target := invariant.Package + "::" + invariant.Test
		if _, exists := seenTargets[target]; exists {
			t.Fatalf("duplicate invariant test target %q", target)
		}
		seenTargets[target] = struct{}{}
		if _, required := requiredIDs[invariant.ID]; required {
			requiredIDs[invariant.ID] = true
		}

		tests := packageTests[invariant.Package]
		if tests == nil {
			tests = finalGatePackageTests(t, root, invariant.Package)
			packageTests[invariant.Package] = tests
		}
		if _, exists := tests[invariant.Test]; !exists {
			available := make([]string, 0, len(tests))
			for name := range tests {
				available = append(available, name)
			}
			sort.Strings(available)
			t.Fatalf("invariant %q references missing executable test %s in %s; available=%v", invariant.ID, invariant.Test, invariant.Package, available)
		}
	}
	for id, present := range requiredIDs {
		if !present {
			t.Fatalf("required final security invariant %q missing from manifest", id)
		}
	}

	digest := sha256.Sum256(raw)
	t.Logf("KOSCHEI_FINAL_SECURITY_MANIFEST_SHA256=%s", hex.EncodeToString(digest[:]))
	t.Logf("KOSCHEI_FINAL_SECURITY_INVARIANT_COUNT=%d", len(manifest.Invariants))
}

func finalGateAPIRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("could not resolve API root %q: %v", root, err)
	}
	return root
}

func finalGatePackageTests(t *testing.T, root, packagePath string) map[string]struct{} {
	t.Helper()
	relative := strings.TrimPrefix(packagePath, "./")
	dir := filepath.Join(root, filepath.FromSlash(relative))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package %s: %v", packagePath, err)
	}
	files := token.NewFileSet()
	tests := map[string]struct{}{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		parsed, err := parser.ParseFile(files, path, nil, 0)
		if err != nil {
			t.Fatalf("parse test file %s: %v", path, err)
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil || !strings.HasPrefix(function.Name.Name, "Test") {
				continue
			}
			tests[function.Name.Name] = struct{}{}
		}
	}
	return tests
}
