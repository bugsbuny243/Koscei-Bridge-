package openapi

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Route struct {
	Pattern  string
	Path     string
	Methods  []string
	AuthTier string
	Source   string
}

type Document map[string]any

func Generate(sourceDir string) ([]byte, []Route, error) {
	routes, err := RegisteredAPIRoutes(sourceDir)
	if err != nil {
		return nil, nil, err
	}
	document := buildDocument(routes)
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return append(encoded, '\n'), routes, nil
}

func RegisteredAPIRoutes(sourceDir string) ([]Route, error) {
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return nil, err
	}
	byPath := map[string]*Route{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		filename := filepath.Join(sourceDir, entry.Name())
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", filename, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 || !isHandleFunc(call.Fun) {
				return true
			}
			pattern, ok := stringLiteral(call.Args[0])
			if !ok || !strings.HasPrefix(pattern, "/api/") {
				return true
			}
			path := normalizePattern(pattern)
			methods := methodsFromExpression(call.Args[1])
			if len(methods) == 0 {
				methods = fallbackMethods(path)
			}
			route := byPath[path]
			if route == nil {
				route = &Route{Pattern: pattern, Path: path, AuthTier: authTier(path, filename), Source: filepath.Base(filename)}
				byPath[path] = route
			}
			route.Methods = uniqueSorted(append(route.Methods, methods...))
			return true
		})
	}
	routes := make([]Route, 0, len(byPath))
	for _, route := range byPath {
		routes = append(routes, *route)
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Path < routes[j].Path })
	return routes, nil
}

func isHandleFunc(expression ast.Expr) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "HandleFunc"
}

func stringLiteral(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	return value, err == nil
}

func methodsFromExpression(expression ast.Expr) []string {
	methods := []string{}
	ast.Inspect(expression, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		identifier, ok := call.Fun.(*ast.Ident)
		if !ok || identifier.Name != "method" {
			return true
		}
		if method := methodName(call.Args[0]); method != "" {
			methods = append(methods, method)
		}
		return true
	})
	return uniqueSorted(methods)
}

func methodName(expression ast.Expr) string {
	if value, ok := stringLiteral(expression); ok {
		return strings.ToLower(strings.TrimSpace(value))
	}
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	mapping := map[string]string{
		"MethodGet": "get", "MethodPost": "post", "MethodPut": "put",
		"MethodPatch": "patch", "MethodDelete": "delete", "MethodHead": "head",
	}
	return mapping[selector.Sel.Name]
}

func normalizePattern(pattern string) string {
	overrides := map[string]string{
		"/api/account/api-keys/":       "/api/account/api-keys/{id}/revoke",
		"/api/owner/radar/jobs/":       "/api/owner/radar/jobs/{id}",
		"/api/v1/radar/jobs/":          "/api/v1/radar/jobs/{id}",
		"/api/jobs/":                   "/api/jobs/{id}",
		"/api/v1/dossier/":             "/api/v1/dossier/{case_ref}",
		"/api/watchlist/":              "/api/watchlist/{id}",
		"/api/webhooks/deliveries/":    "/api/webhooks/deliveries/{id}",
		"/api/webhooks/":               "/api/webhooks/{id}",
	}
	if value := overrides[pattern]; value != "" {
		return value
	}
	return strings.TrimSuffix(pattern, "/")
}

func fallbackMethods(path string) []string {
	overrides := map[string][]string{
		"/api/account/api-keys":                         {"get", "post"},
		"/api/owner/chat":                              {"post"},
		"/api/owner/radar/sources":                     {"get"},
		"/api/owner/feedback":                          {"get", "post"},
		"/api/watchlist":                               {"get", "post"},
		"/api/watchlist/{id}":                          {"delete"},
		"/api/watchlist/alerts":                        {"get"},
		"/api/webhooks":                                {"get", "post"},
		"/api/webhooks/{id}":                           {"delete", "patch"},
		"/api/webhooks/security-alerts":                {"get", "post"},
		"/api/webhooks/deliveries":                     {"get"},
		"/api/webhooks/deliveries/{id}":                {"get", "post"},
	}
	if methods := overrides[path]; len(methods) > 0 {
		return methods
	}
	if strings.HasPrefix(path, "/api/owner/defense/") {
		return []string{"get", "post"}
	}
	return []string{"get", "post"}
}

func authTier(path, filename string) string {
	switch {
	case strings.HasPrefix(path, "/api/owner/"):
		return "owner_session"
	case strings.HasPrefix(path, "/api/v1/scan/") || path == "/api/v1/usage" || strings.HasPrefix(path, "/api/v1/shield/"):
		return "api_key_plus_live_kosch_holder"
	case strings.HasPrefix(path, "/api/watchlist") || strings.HasPrefix(path, "/api/webhooks"):
		return "customer_session_plus_kosch"
	case strings.HasPrefix(path, "/api/account/"):
		return "customer_session_plus_kosch"
	case strings.HasPrefix(path, "/api/auth/wallet/") || path == "/api/auth/token-access" || path == "/api/auth/premium-access" || path == "/api/me" || path == "/api/web3/health/logs":
		return "customer_session"
	case strings.HasPrefix(path, "/api/v1/radar/") || strings.HasPrefix(path, "/api/jobs/") || path == "/api/jobs/token-scan" || path == "/api/v1/token/extensions" || path == "/api/v1/address-poisoning/check" || strings.HasPrefix(path, "/api/agent/") && path != "/api/agent/health":
		return "customer_session_plus_kosch"
	case strings.Contains(filename, "dossier") && strings.HasPrefix(path, "/api/v1/dossier/"):
		return "dossier_access_contract"
	default:
		return "public"
	}
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func buildDocument(routes []Route) Document {
	paths := map[string]any{}
	for _, route := range routes {
		pathItem := map[string]any{}
		for _, method := range route.Methods {
			pathItem[method] = operation(route, method)
		}
		paths[route.Path] = pathItem
	}
	return Document{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   "Koschei Web3 Security API",
			"version": "2026-08-02",
			"description": "Evidence-first API contract generated from the registered server boot chain. " +
				"Static files, HTML pages, robots.txt and ads.txt are intentionally excluded; every registered /api/ route is included. " +
				"WITHHOLD is a valid verdict when required evidence is unavailable and carries unmet_evidence_reasons. Evidence counts are never quality scores.",
		},
		"servers": []any{map[string]any{"url": "/"}},
		"paths":   paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"sessionBearer": map[string]any{"type": "http", "scheme": "bearer", "bearerFormat": "session"},
				"ownerSession":  map[string]any{"type": "apiKey", "in": "cookie", "name": "koschei_owner_session"},
				"developerAPIKey": map[string]any{"type": "apiKey", "in": "header", "name": "X-API-Key"},
			},
			"schemas": schemas(),
		},
	}
}

func operation(route Route, method string) map[string]any {
	operation := map[string]any{
		"operationId":       operationID(method, route.Path),
		"summary":           strings.ToUpper(method) + " " + route.Path,
		"description":       "Registered boot-chain operation. Required evidence that cannot be produced yields a successful withheld result rather than an inferred verdict.",
		"tags":              []string{routeTag(route.Path)},
		"x-koschei-auth-tier": route.AuthTier,
		"parameters":        pathParameters(route.Path),
		"responses":         responses(route.AuthTier),
		"security":          security(route.AuthTier),
	}
	if method == "post" || method == "put" || method == "patch" {
		operation["requestBody"] = map[string]any{
			"required": false,
			"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/GenericRequest"}}},
		}
	}
	return operation
}

func pathParameters(path string) []any {
	parameters := []any{}
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			name := strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")
			parameters = append(parameters, map[string]any{
				"name": name, "in": "path", "required": true,
				"schema": map[string]any{"type": "string", "minLength": 1},
			})
		}
	}
	return parameters
}

func responses(auth string) map[string]any {
	items := map[string]any{
		"200": response("Evidence-backed result, including valid WITHHOLD outcomes.", "#/components/schemas/EvidenceResponse"),
		"400": response("Invalid request.", "#/components/schemas/ErrorResponse"),
		"405": response("Method not allowed.", "#/components/schemas/ErrorResponse"),
		"429": response("Rate or quota limit reached.", "#/components/schemas/ErrorResponse"),
		"500": response("Internal failure; no unsupported verdict is emitted.", "#/components/schemas/ErrorResponse"),
	}
	if auth != "public" {
		items["401"] = response("Identity credential missing or invalid.", "#/components/schemas/ErrorResponse")
		items["403"] = response("Authenticated identity lacks the required access tier.", "#/components/schemas/ErrorResponse")
	}
	return items
}

func response(description, reference string) map[string]any {
	return map[string]any{
		"description": description,
		"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"$ref": reference}}},
	}
}

func security(auth string) []any {
	switch auth {
	case "owner_session":
		return []any{map[string]any{"ownerSession": []string{}}}
	case "api_key_plus_live_kosch_holder":
		return []any{map[string]any{"developerAPIKey": []string{}}}
	case "customer_session", "customer_session_plus_kosch", "dossier_access_contract":
		return []any{map[string]any{"sessionBearer": []string{}}}
	default:
		return []any{}
	}
}

func schemas() map[string]any {
	return map[string]any{
		"GenericRequest": map[string]any{
			"type": "object", "additionalProperties": true,
			"description": "Operation-specific JSON input. Unknown or missing required evidence inputs fail closed.",
		},
		"EvidenceResponse": map[string]any{
			"type": "object",
			"required": []string{"ok"},
			"properties": map[string]any{
				"ok": map[string]any{"type": "boolean"},
				"verdict": map[string]any{"$ref": "#/components/schemas/Verdict"},
				"unmet_evidence_reasons": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"evidence": map[string]any{"type": "array", "items": map[string]any{"type": "object", "additionalProperties": true},
				"data": map[string]any{"type": "object", "additionalProperties": true},
			},
			"additionalProperties": true,
		},
		"Verdict": map[string]any{
			"type": "string",
			"enum": []string{"allow", "block", "deny", "verified", "bounded", "missing", "withhold"},
			"description": "WITHHOLD is an intended non-error outcome when required evidence cannot be produced.",
		},
		"ErrorResponse": map[string]any{
			"type": "object", "required": []string{"error"},
			"properties": map[string]any{
				"error": map[string]any{"type": "string"},
				"code": map[string]any{"type": "string"},
				"details": map[string]any{"type": "object", "additionalProperties": true},
			},
			"additionalProperties": true,
		},
	}
}

func operationID(method, path string) string {
	replacer := strings.NewReplacer("/", "_", "{", "", "}", "", "-", "_")
	return strings.Trim(replacer.Replace(method+"_"+path), "_")
}

func routeTag(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return "api"
}
