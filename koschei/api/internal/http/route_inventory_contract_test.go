package http

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var literalHandleFuncPattern = regexp.MustCompile(`mux\.HandleFunc\("([^"]+)"`)

func registeredAPIRoutesFromSource(t *testing.T) map[string]struct{} {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve route contract test path")
	}
	baseDir := filepath.Dir(currentFile)
	files := []string{
		"server.go",
		"watchlist_routes.go",
		"dossier_routes.go",
		"defense_routes.go",
	}
	out := map[string]struct{}{}
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(baseDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, match := range literalHandleFuncPattern.FindAllStringSubmatch(string(data), -1) {
			path := strings.TrimSpace(match[1])
			if path == "/health" || strings.HasPrefix(path, "/api/") {
				out[path] = struct{}{}
			}
		}
	}
	return out
}

func inventoryAPIRoutes() map[string]struct{} {
	out := map[string]struct{}{}
	for _, group := range productionRouteInventory() {
		for _, entry := range group.Routes {
			fields := strings.Fields(strings.TrimSpace(entry))
			if len(fields) == 0 {
				continue
			}
			path := fields[len(fields)-1]
			if path == "/health" || strings.HasPrefix(path, "/api/") {
				out[path] = struct{}{}
			}
		}
	}
	return out
}

func sortedRouteDifference(left, right map[string]struct{}) []string {
	missing := []string{}
	for path := range left {
		if _, ok := right[path]; !ok {
			missing = append(missing, path)
		}
	}
	sort.Strings(missing)
	return missing
}

func TestProductionRouteInventoryMatchesBootChain(t *testing.T) {
	registered := registeredAPIRoutesFromSource(t)
	inventory := inventoryAPIRoutes()

	if missing := sortedRouteDifference(registered, inventory); len(missing) > 0 {
		t.Fatalf("registered API routes missing from productionRouteInventory: %s", strings.Join(missing, ", "))
	}
	if stale := sortedRouteDifference(inventory, registered); len(stale) > 0 {
		t.Fatalf("productionRouteInventory contains routes not registered in the boot chain: %s", strings.Join(stale, ", "))
	}
}

func TestDatabaseOptionalPathsAreRegistered(t *testing.T) {
	registered := registeredAPIRoutesFromSource(t)
	stale := []string{}
	for path := range databaseOptionalAPIPaths {
		if _, ok := registered[path]; !ok {
			stale = append(stale, path)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Fatalf("databaseOptionalAPIPaths contains unregistered routes: %s", strings.Join(stale, ", "))
	}
}
