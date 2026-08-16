package nodeshield

import (
	"encoding/json"
	"fmt"
	"strings"
)

type dockerInspect struct {
	Name   string `json:"Name"`
	Image  string `json:"Image"`
	Config struct {
		Image        string              `json:"Image"`
		User         string              `json:"User"`
		Env          []string            `json:"Env"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	} `json:"Config"`
	HostConfig struct {
		Privileged     bool     `json:"Privileged"`
		NetworkMode    string   `json:"NetworkMode"`
		PidMode        string   `json:"PidMode"`
		IpcMode        string   `json:"IpcMode"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		CapAdd         []string `json:"CapAdd"`
		SecurityOpt    []string `json:"SecurityOpt"`
		Binds          []string `json:"Binds"`
	} `json:"HostConfig"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
}

// FromDockerInspect converts the JSON emitted by `docker inspect <container>`
// into Node Shield's platform-neutral WorkloadManifest. The artifact hash is
// supplied separately so callers can bind the review to an immutable image or
// exported package digest rather than a mutable image tag.
func FromDockerInspect(data []byte, artifactSHA256 string) (WorkloadManifest, error) {
	var list []dockerInspect
	if err := json.Unmarshal(data, &list); err != nil {
		return WorkloadManifest{}, fmt.Errorf("decode docker inspect: %w", err)
	}
	if len(list) != 1 {
		return WorkloadManifest{}, fmt.Errorf("expected exactly one docker inspect object, got %d", len(list))
	}

	d := list[0]
	m := WorkloadManifest{
		Name:           strings.TrimPrefix(d.Name, "/"),
		ArtifactSHA256: artifactSHA256,
		Image:          d.Config.Image,
		Privileged:     d.HostConfig.Privileged,
		HostNetwork:    d.HostConfig.NetworkMode == "host",
		HostPID:        d.HostConfig.PidMode == "host",
		HostIPC:        d.HostConfig.IpcMode == "host",
		ReadOnlyRootFS: d.HostConfig.ReadonlyRootfs,
		RunAsRoot:      d.Config.User == "" || d.Config.User == "0" || strings.EqualFold(d.Config.User, "root"),
		Capabilities:   append([]string(nil), d.HostConfig.CapAdd...),
	}

	for _, opt := range d.HostConfig.SecurityOpt {
		if strings.EqualFold(strings.TrimSpace(opt), "no-new-privileges:true") {
			m.AllowPrivilegeGain = false
		}
	}

	for _, mount := range d.Mounts {
		m.Mounts = append(m.Mounts, Mount{Source: mount.Source, Target: mount.Destination, ReadOnly: !mount.RW})
		if mount.Source == "/var/run/docker.sock" {
			m.DockerSocket = true
		}
	}

	for _, bind := range d.HostConfig.Binds {
		parts := strings.Split(bind, ":")
		if len(parts) < 2 {
			continue
		}
		ro := len(parts) >= 3 && strings.Contains(parts[2], "ro")
		m.Mounts = append(m.Mounts, Mount{Source: parts[0], Target: parts[1], ReadOnly: ro})
		if parts[0] == "/var/run/docker.sock" {
			m.DockerSocket = true
		}
	}

	for key := range d.Config.ExposedPorts {
		var port int
		if _, err := fmt.Sscanf(key, "%d/", &port); err == nil && port > 0 {
			m.ExposedPorts = append(m.ExposedPorts, port)
		}
	}

	for _, env := range d.Config.Env {
		if i := strings.IndexByte(env, '='); i > 0 {
			m.EnvKeys = append(m.EnvKeys, env[:i])
		}
	}

	return m, nil
}
