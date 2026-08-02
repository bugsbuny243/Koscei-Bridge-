package openapi

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
)

type InventoryRoute struct {
	Path    string
	Methods []string
	Group   string
	Auth    string
}

func RouteInventory(sourceDir string) ([]InventoryRoute, error) {
	filename := filepath.Join(sourceDir, "route_inventory.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filename, err)
	}
	result := []InventoryRoute{}
	found := false
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "productionRouteInventory" || function.Body == nil {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			statement, ok := node.(*ast.ReturnStmt)
			if !ok || len(statement.Results) != 1 {
				return true
			}
			outer, ok := statement.Results[0].(*ast.CompositeLit)
			if !ok {
				return true
			}
			found = true
			for _, element := range outer.Elts {
				groupLiteral, ok := element.(*ast.CompositeLit)
				if !ok {
					continue
				}
				groupName, auth := "", ""
				routes := []string{}
				for _, field := range groupLiteral.Elts {
					pair, ok := field.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := pair.Key.(*ast.Ident)
					if !ok {
						continue
					}
					switch key.Name {
					case "Name":
						groupName, _ = stringLiteral(pair.Value)
					case "Auth":
						auth, _ = stringLiteral(pair.Value)
					case "Routes":
						list, ok := pair.Value.(*ast.CompositeLit)
						if !ok {
							continue
						}
						for _, raw := range list.Elts {
							if value, ok := stringLiteral(raw); ok {
								routes = append(routes, value)
							}
						}
					}
				}
				for _, raw := range routes {
					item, ok := parseInventoryRoute(raw, groupName, auth)
					if ok && strings.HasPrefix(item.Path, "/api/") {
						result = append(result, item)
					}
				}
			}
			return false
		})
	}
	if !found {
		return nil, fmt.Errorf("productionRouteInventory not found in %s", filename)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Path != result[j].Path {
			return result[i].Path < result[j].Path
		}
		return strings.Join(result[i].Methods, ",") < strings.Join(result[j].Methods, ",")
	})
	return result, nil
}

func parseInventoryRoute(raw, group, auth string) (InventoryRoute, bool) {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) == 0 {
		return InventoryRoute{}, false
	}
	pathValue := fields[len(fields)-1]
	if !strings.HasPrefix(pathValue, "/") {
		return InventoryRoute{}, false
	}
	methods := []string{}
	if len(fields) > 1 {
		for _, method := range strings.Split(fields[0], "|") {
			method = strings.ToLower(strings.TrimSpace(method))
			if method != "" {
				methods = append(methods, method)
			}
		}
	}
	return InventoryRoute{
		Path: normalizePattern(pathValue), Methods: uniqueSorted(methods),
		Group: strings.TrimSpace(group), Auth: strings.TrimSpace(auth),
	}, true
}

func enrichRoutesWithInventory(routes []Route, inventory []InventoryRoute) []Route {
	byPath := map[string]InventoryRoute{}
	for _, item := range inventory {
		existing := byPath[item.Path]
		if existing.Path == "" {
			byPath[item.Path] = item
			continue
		}
		existing.Methods = uniqueSorted(append(existing.Methods, item.Methods...))
		byPath[item.Path] = existing
	}
	for index := range routes {
		routes[index].InventoryGroup = routeTag(routes[index].Path)
		routes[index].InventorySource = "boot_chain_fallback"
		if item, ok := byPath[routes[index].Path]; ok {
			routes[index].InventoryAuth = item.Auth
			routes[index].InventoryGroup = item.Group
			routes[index].InventorySource = "route_inventory.go"
			routes[index].AuthTier = normalizedInventoryAuth(item.Auth, routes[index].Path, routes[index].Source)
		}
	}
	return routes
}

func excludedInventoryOperations(routes []Route, inventory []InventoryRoute) []string {
	registered := map[string]map[string]bool{}
	for _, route := range routes {
		methods := map[string]bool{}
		for _, method := range route.Methods {
			methods[method] = true
		}
		registered[route.Path] = methods
	}
	excluded := []string{}
	for _, item := range inventory {
		methods, pathRegistered := registered[item.Path]
		if len(item.Methods) == 0 {
			if !pathRegistered {
				excluded = append(excluded, item.Path)
			}
			continue
		}
		for _, method := range item.Methods {
			if !pathRegistered || !methods[method] {
				excluded = append(excluded, strings.ToUpper(method)+" "+item.Path)
			}
		}
	}
	sort.Strings(excluded)
	return uniqueStrings(excluded)
}

func normalizedInventoryAuth(inventoryAuth, path, filename string) string {
	switch strings.TrimSpace(inventoryAuth) {
	case "public_rate_limited":
		return "public"
	case "owner_session":
		return "owner_session"
	case "customer_session_plus_kosch", "customer_session_plus_kosch_for_api_keys":
		return authTier(path, filename)
	case "api_key_plus_live_kosch_holder":
		return "api_key_plus_live_kosch_holder"
	default:
		return authTier(path, filename)
	}
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}
