package nodeshield

import "testing"

func TestFromDockerInspectDetectsHostRisk(t *testing.T) {
	data := []byte(`[{"Name":"/demo","Config":{"Image":"demo:latest","User":"root","Env":["TOKEN=x"],"ExposedPorts":{"8080/tcp":{}}},"HostConfig":{"Privileged":false,"NetworkMode":"host","PidMode":"","IpcMode":"","ReadonlyRootfs":true,"CapAdd":["NET_ADMIN"],"SecurityOpt":[],"Binds":["/var/run/docker.sock:/var/run/docker.sock"]},"Mounts":[]}]`)
	m, err := FromDockerInspect(data, "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if !m.HostNetwork || !m.DockerSocket || !m.RunAsRoot {
		t.Fatalf("expected host network, docker socket, and root detection: %#v", m)
	}
	if len(m.EnvKeys) != 1 || m.EnvKeys[0] != "TOKEN" {
		t.Fatalf("expected environment key extraction, got %#v", m.EnvKeys)
	}
	if Scan(m).Verdict != VerdictBlock {
		t.Fatalf("expected normalized workload to be blocked")
	}
}
