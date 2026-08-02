package openapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestCommittedOpenAPIMatchesRegisteredAPIRoutes(t *testing.T) {
	apiRoot, sourceDir, documentPath := testPaths(t)
	generated, routes, err := Generate(sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(generated) != string(committed) {
		t.Fatalf("openapi.yaml drifted from registered boot-chain routes; run (cd %s && go run ./cmd/openapi-gen)", apiRoot)
	}

	var document map[string]any
	if err := json.Unmarshal(committed, &document); err != nil {
		t.Fatal(err)
	}
	if err := assertRouteCoverage(routes, document); err != nil {
		t.Fatal(err)
	}
}

func TestOpenAPIDriftCheckRejectsDeliberateUndocumentedRoute(t *testing.T) {
	_, _, documentPath := testPaths(t)
	committed, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(committed, &document); err != nil {
		t.Fatal(err)
	}
	routes := []Route{{Path: "/api/deliberate-undocumented", Methods: []string{"get"}}}
	if err := assertRouteCoverage(routes, document); err == nil || !strings.Contains(err.Error(), "/api/deliberate-undocumented") {
		t.Fatalf("deliberate undocumented route did not fail drift check: %v", err)
	}
}

func TestOpenAPIDocumentsWithholdAsValidEvidenceOutcome(t *testing.T) {
	_, _, documentPath := testPaths(t)
	committed, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(committed, &document); err != nil {
		t.Fatal(err)
	}
	components := object(document["components"])
	schemas := object(components["schemas"])
	verdict := object(schemas["Verdict"])
	enum, _ := verdict["enum"].([]any)
	foundWithhold := false
	for _, value := range enum {
		if value == "withhold" {
			foundWithhold = true
		}
	}
	if !foundWithhold {
		t.Fatal("Verdict enum does not include withhold")
	}
	response := object(schemas["EvidenceResponse"])
	properties := object(response["properties"])
	if _, ok := properties["unmet_evidence_reasons"]; !ok {
		t.Fatal("withheld response does not publish unmet_evidence_reasons")
	}
}

func TestRouteInventoryExclusionsMatchDocumentAndSyntheticStaleRouteIsRejected(t *testing.T) {
	_, sourceDir, documentPath := testPaths(t)
	routes, err := RegisteredAPIRoutes(sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := RouteInventory(sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	actualExcluded := excludedInventoryOperations(routes, inventory)

	committed, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(committed, &document); err != nil {
		t.Fatal(err)
	}
	rawExcluded, ok := document["x-koschei-excluded-unregistered-inventory-operations"].([]any)
	if !ok {
		t.Fatal("OpenAPI document does not publish excluded inventory operations")
	}
	published := make([]string, 0, len(rawExcluded))
	for _, value := range rawExcluded {
		text, ok := value.(string)
		if ok {
			published = append(published, text)
		}
	}
	sort.Strings(published)
	sort.Strings(actualExcluded)
	if strings.Join(published, "\n") != strings.Join(actualExcluded, "\n") {
		t.Fatalf("published stale inventory exclusions=%v actual=%v", published, actualExcluded)
	}

	synthetic := append(append([]InventoryRoute(nil), inventory...), InventoryRoute{
		Path: "/api/deliberate-stale-inventory", Methods: []string{"get"},
		Group: "test", Auth: "public_rate_limited",
	})
	syntheticExcluded := excludedInventoryOperations(routes, synthetic)
	found := false
	for _, operation := range syntheticExcluded {
		if operation == "GET /api/deliberate-stale-inventory" {
			found = true
		}
	}
	if !found {
		t.Fatalf("synthetic stale inventory operation was not excluded: %v", syntheticExcluded)
	}
	if _, live := object(document["paths"])["/api/deliberate-stale-inventory"]; live {
		t.Fatal("synthetic stale inventory route appeared as a live OpenAPI path")
	}
}

func TestRegisteredRoutesUseInventoryMetadataWhenAvailable(t *testing.T) {
	_, sourceDir, _ := testPaths(t)
	routes, err := RegisteredAPIRoutes(sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	matched := 0
	for _, route := range routes {
		if route.InventorySource != "route_inventory.go" {
			continue
		}
		matched++
		if route.InventoryGroup == "" || route.InventoryAuth == "" {
			t.Fatalf("route %s lacks inventory group/auth metadata: %+v", route.Path, route)
		}
	}
	if matched == 0 {
		t.Fatal("no registered route reconciled with route_inventory.go")
	}
}

func assertRouteCoverage(routes []Route, document map[string]any) error {
	paths := object(document["paths"])
	for _, route := range routes {
		pathItem, ok := paths[route.Path]
		if !ok {
			return routeError(route.Path, "path is not documented")
		}
		operations := object(pathItem)
		for _, method := range route.Methods {
			operationValue, ok := operations[method]
			if !ok {
				return routeError(method+" "+route.Path, "operation is not documented")
			}
			operation := object(operationValue)
			if operation["x-koschei-auth-tier"] == nil {
				return routeError(method+" "+route.Path, "auth tier is not documented")
			}
			if operation["responses"] == nil || operation["parameters"] == nil {
				return routeError(method+" "+route.Path, "responses or parameters are missing")
			}
		}
	}
	return nil
}

func routeError(route, message string) error {
	return &coverageError{route: route, message: message}
}

type coverageError struct {
	route   string
	message string
}

func (e *coverageError) Error() string { return e.route + ": " + e.message }

func object(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func testPaths(t *testing.T) (apiRoot, sourceDir, documentPath string) {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	apiRoot = filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	sourceDir = filepath.Join(apiRoot, "internal", "http")
	documentPath = filepath.Join(apiRoot, "openapi.yaml")
	return
}
