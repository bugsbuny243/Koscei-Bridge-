package nodeshield

type Severity string

const (
	SeverityInfo Severity = "info"
	SeverityLow Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh Severity = "high"
	SeverityCritical Severity = "critical"
)

type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictWarn Verdict = "warn"
	VerdictBlock Verdict = "block"
)

type Mount struct {
	Type string `json:"type,omitempty"`
	Source string `json:"source"`
	Target string `json:"target"`
	ReadOnly bool `json:"read_only"`
}

type DeviceMapping struct {
	HostPath string `json:"host_path"`
	ContainerPath string `json:"container_path"`
	Permissions string `json:"permissions,omitempty"`
}

type WorkloadManifest struct {
	Name string `json:"name"`
	Publisher string `json:"publisher,omitempty"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	Image string `json:"image,omitempty"`
	Privileged bool `json:"privileged"`
	HostNetwork bool `json:"host_network"`
	HostPID bool `json:"host_pid"`
	HostIPC bool `json:"host_ipc"`
	DockerSocket bool `json:"docker_socket"`
	AllowPrivilegeGain bool `json:"allow_privilege_gain"`
	ReadOnlyRootFS bool `json:"read_only_root_fs"`
	RunAsRoot bool `json:"run_as_root"`
	UserIdentityVerified bool `json:"user_identity_verified"`
	Mounts []Mount `json:"mounts,omitempty"`
	Devices []DeviceMapping `json:"devices,omitempty"`
	ExposedPorts []int `json:"exposed_ports,omitempty"`
	OutboundHosts []string `json:"outbound_hosts,omitempty"`
	EnvKeys []string `json:"env_keys,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type Finding struct {
	ID string `json:"id"`
	Severity Severity `json:"severity"`
	Title string `json:"title"`
	Description string `json:"description"`
	Remediation string `json:"remediation,omitempty"`
}

type Report struct {
	SchemaVersion string `json:"schema_version"`
	Workload string `json:"workload"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	Verdict Verdict `json:"verdict"`
	Findings []Finding `json:"findings"`
}
