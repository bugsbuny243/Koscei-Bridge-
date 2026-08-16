package nodeshield

import (
	"net"
	"path/filepath"
	"strconv"
	"strings"
)

type RuntimeAction string

const (
	RuntimeAllow RuntimeAction = "allow"
	RuntimeDeny  RuntimeAction = "deny"
	RuntimeKill  RuntimeAction = "kill"
)

type RuntimeEventKind string

const (
	EventNetworkConnect RuntimeEventKind = "network_connect"
	EventFileOpen       RuntimeEventKind = "file_open"
	EventProcessExec    RuntimeEventKind = "process_exec"
	EventPrivilege      RuntimeEventKind = "privilege_change"
)

// Write and exec authorization never trusts lexical user paths. Collectors must
// provide an OS/kernel-resolved target and attest that it identifies the object
// actually acted on at the enforcement point.
type RuntimeEvent struct {
	Kind                       RuntimeEventKind `json:"kind"`
	Destination                string           `json:"destination,omitempty"`
	Path                       string           `json:"path,omitempty"`
	ResolvedPath               string           `json:"resolved_path,omitempty"`
	PathIdentityVerified       bool             `json:"path_identity_verified,omitempty"`
	Executable                 string           `json:"executable,omitempty"`
	ResolvedExecutable         string           `json:"resolved_executable,omitempty"`
	ExecutableIdentityVerified bool             `json:"executable_identity_verified,omitempty"`
	Write                      bool             `json:"write,omitempty"`
}

type RuntimePolicy struct {
	ArtifactSHA256 string `json:"artifact_sha256"`
	// AllowedHosts is retained for schema compatibility, but each entry is an
	// exact host:port endpoint (or wildcard-host:port such as *.example.com:443).
	AllowedHosts        []string `json:"allowed_hosts,omitempty"`
	AllowedWritePaths   []string `json:"allowed_write_paths,omitempty"`
	AllowedExecutables  []string `json:"allowed_executables,omitempty"`
	DenyPrivilegeChange bool     `json:"deny_privilege_change"`
}

type RuntimeDecision struct {
	Action      RuntimeAction `json:"action"`
	RuleID      string        `json:"rule_id"`
	Description string        `json:"description"`
}

func EvaluateRuntimeEvent(policy RuntimePolicy, observedArtifactSHA256 string, event RuntimeEvent) RuntimeDecision {
	if strings.TrimSpace(policy.ArtifactSHA256) == "" || !strings.EqualFold(strings.TrimSpace(policy.ArtifactSHA256), strings.TrimSpace(observedArtifactSHA256)) {
		return RuntimeDecision{Action: RuntimeKill, RuleID: "NS-RT-PROV-001", Description: "running artifact identity does not match the approved runtime policy"}
	}

	switch event.Kind {
	case EventPrivilege:
		if policy.DenyPrivilegeChange { return RuntimeDecision{Action: RuntimeKill, RuleID: "NS-RT-AUTH-001", Description: "runtime privilege change is forbidden"} }
		return allowRuntime()
	case EventNetworkConnect:
		endpoint := normalizeEndpoint(event.Destination)
		if endpoint == "" || !endpointAllowed(endpoint, policy.AllowedHosts) {
			return RuntimeDecision{Action: RuntimeDeny, RuleID: "NS-RT-NET-001", Description: "outbound endpoint is outside the approved host-and-port boundary"}
		}
		return allowRuntime()
	case EventFileOpen:
		if !event.Write { return allowRuntime() }
		if !event.PathIdentityVerified {
			return RuntimeDecision{Action: RuntimeDeny, RuleID: "NS-RT-FS-002", Description: "write target lacks verified resolved-path identity"}
		}
		path := filepath.Clean(strings.TrimSpace(event.ResolvedPath))
		if path == "." || path == "/" || !pathAllowed(path, policy.AllowedWritePaths) {
			return RuntimeDecision{Action: RuntimeDeny, RuleID: "NS-RT-FS-001", Description: "resolved write target is outside the approved filesystem boundary"}
		}
		return allowRuntime()
	case EventProcessExec:
		if !event.ExecutableIdentityVerified {
			return RuntimeDecision{Action: RuntimeDeny, RuleID: "NS-RT-PROC-002", Description: "process execution lacks verified resolved executable identity"}
		}
		exe := filepath.Clean(strings.TrimSpace(event.ResolvedExecutable))
		if exe == "." || exe == "/" || !exactStringAllowed(exe, policy.AllowedExecutables) {
			return RuntimeDecision{Action: RuntimeDeny, RuleID: "NS-RT-PROC-001", Description: "resolved process execution is outside the approved executable set"}
		}
		return allowRuntime()
	default:
		return RuntimeDecision{Action: RuntimeDeny, RuleID: "NS-RT-UNK-001", Description: "unknown runtime event kind is denied by default"}
	}
}

func allowRuntime() RuntimeDecision { return RuntimeDecision{Action: RuntimeAllow, RuleID: "NS-RT-ALLOW", Description: "event is within the approved runtime boundary"} }

func normalizeEndpoint(destination string) string {
	destination = strings.TrimSpace(strings.ToLower(destination))
	host, port, err := net.SplitHostPort(destination)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" { return "" }
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if !validEndpointHost(host, false) { return "" }
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 { return "" }
	return net.JoinHostPort(host, strconv.FormatUint(p, 10))
}

func normalizePolicyEndpoint(destination string) string {
	destination = strings.TrimSpace(strings.ToLower(destination))
	host, port, err := net.SplitHostPort(destination)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" { return "" }
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if !validEndpointHost(host, true) { return "" }
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 { return "" }
	return net.JoinHostPort(host, strconv.FormatUint(p, 10))
}

func validEndpointHost(host string, wildcard bool) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" || host == "*" { return false }
	if wildcard && strings.HasPrefix(host, "*.") {
		host = strings.TrimPrefix(host, "*.")
		if host == "" { return false }
	} else if strings.Contains(host, "*") { return false }
	if ip := net.ParseIP(host); ip != nil { return true }
	if len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") { return false }
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' { return false }
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' { continue }
			return false
		}
	}
	return true
}

func endpointAllowed(endpoint string, allowed []string) bool {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil { return false }
	host = strings.ToLower(strings.Trim(host, "[]"))
	for _, raw := range allowed {
		candidate := normalizePolicyEndpoint(raw)
		if candidate == "" { continue }
		chost, cport, err := net.SplitHostPort(candidate)
		if err != nil || cport != port { continue }
		chost = strings.Trim(chost, "[]")
		if strings.HasPrefix(chost, "*.") {
			suffix := strings.TrimPrefix(chost, "*")
			if strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".") { return true }
			continue
		}
		if host == chost { return true }
	}
	return false
}

func pathAllowed(path string, allowed []string) bool {
	for _, candidate := range allowed {
		candidate = filepath.Clean(strings.TrimSpace(candidate))
		if candidate == "." || candidate == "/" { continue }
		if path == candidate || strings.HasPrefix(path, candidate+string(filepath.Separator)) { return true }
	}
	return false
}

func exactStringAllowed(value string, allowed []string) bool {
	for _, candidate := range allowed {
		candidate = filepath.Clean(strings.TrimSpace(candidate))
		if candidate == "." || candidate == "/" { continue }
		if value == candidate { return true }
	}
	return false
}
