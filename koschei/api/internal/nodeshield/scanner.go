package nodeshield

import (
	"encoding/hex"
	"path/filepath"
	"strings"
)

var sensitiveHostPrefixes = []string{
	"/var/run/docker.sock", "/run/docker.sock", "/etc", "/root", "/home", "/var/lib/docker", "/proc", "/sys", "/dev",
}
var dangerousCapabilities = map[string]struct{}{"SYS_ADMIN":{},"SYS_PTRACE":{},"NET_ADMIN":{},"NET_RAW":{},"DAC_OVERRIDE":{},"SYS_MODULE":{}}

func validSHA256(v string) bool { v=strings.TrimSpace(v); if len(v)!=64{return false}; _,err:=hex.DecodeString(v); return err==nil }
func isSHA256Hex(v string) bool { return validSHA256(v) }

func pathContainsOrIsContainedBy(a,b string) bool {
	a=filepath.Clean(a); b=filepath.Clean(b)
	if a==b{return true}
	// filepath containment needs a root special-case: "/" + separator would
	// otherwise become "//" and fail to recognize that root encloses all absolute paths.
	if a==string(filepath.Separator){return filepath.IsAbs(b)}
	if b==string(filepath.Separator){return filepath.IsAbs(a)}
	sep:=string(filepath.Separator)
	return strings.HasPrefix(a,b+sep)||strings.HasPrefix(b,a+sep)
}

func Scan(m WorkloadManifest) Report {
	findings:=make([]Finding,0,8)
	add:=func(id string,sev Severity,title,description,remediation string){findings=append(findings,Finding{ID:id,Severity:sev,Title:title,Description:description,Remediation:remediation})}
	if !validSHA256(m.ArtifactSHA256){add("NS-PROV-001",SeverityHigh,"Invalid artifact identity","The workload is not bound to a complete SHA-256 digest, so substitutions cannot be reliably detected.","Pin the exact workload artifact with a 64-hex-character SHA-256 digest before installation.")}
	if !m.UserIdentityVerified{add("NS-ISO-006",SeverityHigh,"Unverified runtime user identity","The adapter could not prove the effective runtime UID. A named image user can resolve to UID 0 through image account metadata.","Resolve and attest the effective runtime UID before allowing the workload.")}
	if m.Privileged{add("NS-ISO-001",SeverityCritical,"Privileged container","Privileged execution can collapse container isolation and expose host devices and kernel attack surface.","Run unprivileged and grant only narrowly required capabilities.")}
	if m.DockerSocket{add("NS-ISO-002",SeverityCritical,"Docker socket exposed","Access to the Docker daemon socket can allow control over other containers and commonly enables host-level takeover.","Do not mount the Docker socket into untrusted workloads.")}
	if m.HostPID||m.HostIPC{add("NS-ISO-003",SeverityHigh,"Host namespace sharing","Sharing host PID or IPC namespaces weakens workload isolation and can expose host processes or inter-process resources.","Use isolated PID and IPC namespaces.")}
	if m.HostNetwork{add("NS-NET-001",SeverityHigh,"Host network enabled","Host networking removes network namespace isolation and may expose local services that should not be reachable by the workload.","Use an isolated network namespace with an explicit outbound allowlist.")}
	if m.AllowPrivilegeGain{add("NS-ISO-004",SeverityHigh,"Privilege escalation permitted","The process is permitted to gain additional privileges during execution.","Enable no-new-privileges / disallow privilege gain.")}
	if m.RunAsRoot{add("NS-ISO-005",SeverityMedium,"Runs as root","Root inside a container increases the impact of runtime and isolation vulnerabilities.","Run as a dedicated non-root UID/GID.")}
	if !m.ReadOnlyRootFS{add("NS-FS-001",SeverityLow,"Writable root filesystem","A writable root filesystem increases persistence and tampering opportunities inside the workload.","Use a read-only root filesystem and explicit writable data volumes.")}
	for _,mount:=range m.Mounts{
		if mount.Type!=""&&!strings.EqualFold(mount.Type,"bind"){continue};source:=filepath.Clean(strings.TrimSpace(mount.Source))
		for _,prefix:=range sensitiveHostPrefixes{if pathContainsOrIsContainedBy(source,prefix){sev:=SeverityHigh;if pathContainsOrIsContainedBy(source,"/var/run/docker.sock")||pathContainsOrIsContainedBy(source,"/run/docker.sock")||pathContainsOrIsContainedBy(source,"/proc")||pathContainsOrIsContainedBy(source,"/sys")||pathContainsOrIsContainedBy(source,"/dev"){sev=SeverityCritical};add("NS-FS-002",sev,"Sensitive host mount","The workload mounts a security-sensitive host path: "+source+".","Remove the host mount or replace it with a narrowly scoped, read-only data volume.");break}}
	}
	for _,device:=range m.Devices{if strings.TrimSpace(device.HostPath)!=""{add("NS-DEV-001",SeverityCritical,"Raw host device exposed","The workload receives direct access to host device "+device.HostPath+", which can bypass normal filesystem and container isolation.","Remove raw device mappings from untrusted workloads.")}}
	for _,raw:=range m.Capabilities{capName:=strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(raw)),"CAP_");if capName=="ALL"{add("NS-CAP-001",SeverityCritical,"All Linux capabilities requested","The workload requests all Linux capabilities, collapsing the intended capability boundary.","Grant only the minimal explicitly required capabilities.");continue};if _,ok:=dangerousCapabilities[capName];ok{add("NS-CAP-001",SeverityHigh,"Dangerous Linux capability","The workload requests capability "+capName+", which materially expands kernel or host control.","Drop the capability unless a documented, unavoidable requirement exists.")}}
	hasOutboundBoundary:=false;for _,host:=range m.OutboundHosts{if normalizePolicyEndpoint(host)!=""{hasOutboundBoundary=true;break}};if !hasOutboundBoundary{add("NS-NET-002",SeverityMedium,"Unbounded outbound intent","No syntactically enforceable outbound host-and-port destination set was supplied, so the reviewed workload has no network egress boundary.","Declare exact host:port destinations (or controlled *.domain:port wildcards) required by the workload.")}
	verdict:=VerdictAllow;for _,f:=range findings{if f.Severity==SeverityCritical{verdict=VerdictBlock;break};if f.Severity==SeverityHigh||f.Severity==SeverityMedium{verdict=VerdictWarn}}
	return Report{SchemaVersion:"nodeshield.report.v0.1",Workload:m.Name,ArtifactSHA256:m.ArtifactSHA256,Verdict:verdict,Findings:findings}
}
