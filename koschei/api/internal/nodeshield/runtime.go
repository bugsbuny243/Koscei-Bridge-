package nodeshield

import (
	"net"
	"path/filepath"
	"strings"
)

// RuntimeAction is the enforcement decision for a single observed event.
type RuntimeAction string

const (
	RuntimeAllow RuntimeAction = "allow"
	RuntimeDeny  RuntimeAction = "deny"
	RuntimeKill  RuntimeAction = "kill"
)

// RuntimeEventKind is a normalized behavior observed while a workload is running.
type RuntimeEventKind string

const (
	EventNetworkConnect RuntimeEventKind = "network_connect"
	EventFileOpen       RuntimeEventKind = "file_open"
	EventProcessExec    RuntimeEventKind = "process_exec"
	EventPrivilege      RuntimeEventKind = "privilege_change"
)

// RuntimeEvent intentionally carries only normalized security-relevant fields.
// Platform collectors (Docker/eBPF/SoloHost) translate native events into this type.
type RuntimeEvent struct {
	Kind        RuntimeEventKind `json:"kind"`
	Destination string           `json:"destination,omitempty"`
	Path        string           `json:"path,omitempty"`
	Executable  string           `json:"executable,omitempty"`
	Write       bool             `json:"write,omitempty"`
}

// RuntimePolicy binds live behavior to the exact workload artifact reviewed at install time.
type RuntimePolicy struct {
	ArtifactSHA256      string   `json:"artifact_sha256"`
	AllowedHosts        []string `json:"allowed_hosts,omitempty"`
	AllowedWritePaths   []string `json:"allowed_write_paths,omitempty"`
	AllowedExecutables  []string `json:"allowed_executables,omitempty"`
	DenyPrivilegeChange bool     `json:"deny_privilege_change"`
}

// RuntimeDecision is deterministic and fail-closed. Kill means the observed
// behavior crosses a trust boundary and the supervisor should stop the workload.
type RuntimeDecision struct {
	Action      RuntimeAction `json:"action"`
	RuleID      string        `json:"rule_id"`
	Description string        `json:"description"`
}

// EvaluateRuntimeEvent evaluates one normalized live event against an artifact-bound policy.
func EvaluateRuntimeEvent(policy RuntimePolicy, observedArtifactSHA256 string, event RuntimeEvent) RuntimeDecision {
	if strings.TrimSpace(policy.ArtifactSHA256) == "" || !strings.EqualFold(strings.TrimSpace(policy.ArtifactSHA256), strings.TrimSpace(observedArtifactSHA256)) {
		return RuntimeDecision{Action: RuntimeKill, RuleID: "NS-RT-PROV-001", Description: "running artifact identity does not match the approved runtime policy"}
	}

	switch event.Kind {
	case EventPrivilege:
		if policy.DenyPrivilegeChange {
			return RuntimeDecision{Action: RuntimeKill, RuleID: "NS-RT-AUTH-001", Description: "runtime privilege change is forbidden"}
		}
		return allowRuntime()

	case EventNetworkConnect:
		host := normalizeHost(event.Destination)
		if host == "" || !hostAllowed(host, policy.AllowedHosts) {
			return RuntimeDecision{Action: RuntimeDeny, RuleID: "NS-RT-NET-001", Description: "outbound destination is outside the approved network boundary"}
		}
		return allowRuntime()

	case EventFileOpen:
		if !event.Write {
			return allowRuntime()
		}
		path := filepath.Clean(strings.TrimSpace(event.Path))
		if path == "." || !pathAllowed(path, policy.AllowedWritePaths) {
			return RuntimeDecision{Action: RuntimeDeny, RuleID: "NS-RT-FS-001", Description: "write target is outside the approved filesystem boundary"}
		}
		return allowRuntime()

	case EventProcessExec:
		exe := filepath.Clean(strings.TrimSpace(event.Executable))
		if exe == "." || !exactStringAllowed(exe, policy.AllowedExecutables) {
			return RuntimeDecision{Action: RuntimeDeny, RuleID: "NS-RT-PROC-001", Description: "process execution is outside the approved executable set"}
		}
		return allowRuntime()

	default:
		return RuntimeDecision{Action: RuntimeDeny, RuleID: "NS-RT-UNK-001", Description: "unknown runtime event kind is denied by default"}
	}
}

func allowRuntime() RuntimeDecision {
	return RuntimeDecision{Action: RuntimeAllow, RuleID: "NS-RT-ALLOW", Description: "event is within the approved runtime boundary"}
}

func normalizeHost(destination string) string {
	destination = strings.TrimSpace(strings.ToLower(destination))
	if destination == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(destination); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(destination, "[]")
}

func hostAllowed(host string, allowed []string) bool {
	for _, candidate := range allowed {
		candidate = strings.TrimSpace(strings.ToLower(candidate))
		if candidate == "" {
			continue
		}
		if strings.HasPrefix(candidate, "*.") {
			suffix := strings.TrimPrefix(candidate, "*")
			if strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".") {
				return true
			}
			continue
		}
		if host == candidate {
			return true
		}
	}
	return false
}

func pathAllowed(path string, allowed []string) bool {
	for _, candidate := range allowed {
		candidate = filepath.Clean(strings.TrimSpace(candidate))
		if candidate == "." {
			continue
		}
		if path == candidate || strings.HasPrefix(path, candidate+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func exactStringAllowed(value string, allowed []string) bool {
	for _, candidate := range allowed {
		if value == filepath.Clean(strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}
