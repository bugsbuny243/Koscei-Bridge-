package nodeshield

// Severity is the impact assigned to a finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Verdict is the install-time decision emitted by Node Shield.
type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictWarn  Verdict = "warn"
	VerdictBlock Verdict = "block"
)

// Mount describes a container/host filesystem mapping.
type Mount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

// WorkloadManifest is the normalized security-relevant view of a SoloHost,
// Docker, or OCI workload. Adapters should translate platform-specific
// metadata into this type before policy evaluation.
type WorkloadManifest struct {
	Name               string            `json:"name"`
	Publisher          string            `json:"publisher,omitempty"`
	ArtifactSHA256     string            `json:"artifact_sha256"`
	Image              string            `json:"image,omitempty"`
	Privileged         bool              `json:"privileged"`
	HostNetwork        bool              `json:"host_network"`
	HostPID            bool              `json:"host_pid"`
	HostIPC            bool              `json:"host_ipc"`
	DockerSocket       bool              `json:"docker_socket"`
	AllowPrivilegeGain bool              `json:"allow_privilege_gain"`
	ReadOnlyRootFS     bool              `json:"read_only_root_fs"`
	RunAsRoot          bool              `json:"run_as_root"`
	Mounts             []Mount           `json:"mounts,omitempty"`
	ExposedPorts       []int             `json:"exposed_ports,omitempty"`
	OutboundHosts      []string          `json:"outbound_hosts,omitempty"`
	EnvKeys            []string          `json:"env_keys,omitempty"`
	Capabilities       []string          `json:"capabilities,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// Finding is a single policy violation or risk signal.
type Finding struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation,omitempty"`
}

// Report is the deterministic install-time security verdict for a workload.
type Report struct {
	SchemaVersion string    `json:"schema_version"`
	Workload      string    `json:"workload"`
	ArtifactSHA256 string   `json:"artifact_sha256"`
	Score         int       `json:"score"`
	Verdict       Verdict   `json:"verdict"`
	Findings      []Finding `json:"findings"`
}
