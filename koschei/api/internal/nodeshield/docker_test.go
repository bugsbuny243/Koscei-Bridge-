package nodeshield

import "testing"

func TestFromDockerInspectDetectsHostRisk(t *testing.T) {
	data := []byte(`[{"Name":"/demo","Config":{"Image":"demo:latest","User":"0:1000","Env":["TOKEN=x"],"ExposedPorts":{"8080/tcp":{}}},"HostConfig":{"Privileged":false,"NetworkMode":"host","PidMode":"","IpcMode":"","ReadonlyRootfs":true,"CapAdd":["CAP_NET_ADMIN"],"SecurityOpt":[],"Binds":["/var/run/docker.sock:/var/run/docker.sock"],"Devices":[{"PathOnHost":"/dev/sda","PathInContainer":"/dev/x","CgroupPermissions":"rwm"}]},"Mounts":[{"Type":"bind","Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock","RW":true}]}]`)
	m, err := FromDockerInspect(data, testSHA)
	if err != nil { t.Fatal(err) }
	if !m.HostNetwork || !m.DockerSocket || !m.RunAsRoot || !m.AllowPrivilegeGain {
		t.Fatalf("expected host network, docker socket, root and privilege-gain detection: %#v", m)
	}
	if len(m.Mounts) != 1 { t.Fatalf("expected duplicate bind metadata to be deduplicated, got %#v", m.Mounts) }
	if len(m.Devices) != 1 || m.Devices[0].HostPath != "/dev/sda" { t.Fatalf("expected raw device mapping, got %#v", m.Devices) }
	if len(m.EnvKeys) != 1 || m.EnvKeys[0] != "TOKEN" { t.Fatalf("expected environment key extraction, got %#v", m.EnvKeys) }
	if Scan(m).Verdict != VerdictBlock { t.Fatalf("expected normalized workload to be blocked") }
}

func TestFromDockerInspectHonorsNoNewPrivilegesAndNamedVolumes(t *testing.T) {
	data := []byte(`[{"Name":"/safe","Config":{"Image":"demo:latest","User":"1000:1000"},"HostConfig":{"ReadonlyRootfs":true,"SecurityOpt":["no-new-privileges:true"]},"Mounts":[{"Type":"volume","Source":"/var/lib/docker/volumes/data/_data","Destination":"/data","RW":true}]}]`)
	m, err := FromDockerInspect(data, testSHA)
	if err != nil { t.Fatal(err) }
	if m.AllowPrivilegeGain { t.Fatal("expected no-new-privileges to disable privilege gain") }
	if m.RunAsRoot { t.Fatal("expected UID 1000 to be non-root") }
	if len(m.Mounts) != 1 || m.Mounts[0].Type != "volume" { t.Fatalf("expected named volume type to survive normalization: %#v", m.Mounts) }
}
