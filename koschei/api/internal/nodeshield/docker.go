package nodeshield

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type dockerInspect struct {
	Name  string `json:"Name"`
	Image string `json:"Image"`
	Config struct {
		Image string `json:"Image"`
		User string `json:"User"`
		Env []string `json:"Env"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	} `json:"Config"`
	HostConfig struct {
		Privileged bool `json:"Privileged"`
		NetworkMode string `json:"NetworkMode"`
		PidMode string `json:"PidMode"`
		IpcMode string `json:"IpcMode"`
		ReadonlyRootfs bool `json:"ReadonlyRootfs"`
		CapAdd []string `json:"CapAdd"`
		SecurityOpt []string `json:"SecurityOpt"`
		Binds []string `json:"Binds"`
		Devices []struct {
			PathOnHost string `json:"PathOnHost"`
			PathInContainer string `json:"PathInContainer"`
			CgroupPermissions string `json:"CgroupPermissions"`
		} `json:"Devices"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type string `json:"Type"`
		Source string `json:"Source"`
		Destination string `json:"Destination"`
		RW bool `json:"RW"`
	} `json:"Mounts"`
}

func FromDockerInspect(data []byte, artifactSHA256 string) (WorkloadManifest, error) {
	var list []dockerInspect
	if err := json.Unmarshal(data, &list); err != nil { return WorkloadManifest{}, fmt.Errorf("decode docker inspect: %w", err) }
	if len(list) != 1 { return WorkloadManifest{}, fmt.Errorf("expected exactly one docker inspect object, got %d", len(list)) }
	d := list[0]

	userPart := strings.TrimSpace(d.Config.User)
	if i := strings.IndexByte(userPart, ':'); i >= 0 { userPart = userPart[:i] }
	runAsRoot, userVerified := resolveDockerUserSpec(userPart)
	m := WorkloadManifest{
		Name: strings.TrimPrefix(d.Name, "/"), ArtifactSHA256: artifactSHA256, Image: d.Config.Image,
		Privileged:d.HostConfig.Privileged, HostNetwork:d.HostConfig.NetworkMode=="host", HostPID:d.HostConfig.PidMode=="host", HostIPC:d.HostConfig.IpcMode=="host",
		ReadOnlyRootFS:d.HostConfig.ReadonlyRootfs, RunAsRoot:runAsRoot, UserIdentityVerified:userVerified,
		AllowPrivilegeGain:true, Capabilities:append([]string(nil), d.HostConfig.CapAdd...),
	}
	for _, opt := range d.HostConfig.SecurityOpt {
		if strings.EqualFold(strings.TrimSpace(opt), "no-new-privileges:true") { m.AllowPrivilegeGain=false; break }
	}

	seenMounts := map[string]struct{}{}
	appendMount := func(mt Mount) {
		key := strings.ToLower(mt.Type)+"\x00"+mt.Source+"\x00"+mt.Target+fmt.Sprintf("\x00%t", mt.ReadOnly)
		if _, ok := seenMounts[key]; ok { return }
		seenMounts[key]=struct{}{}
		m.Mounts=append(m.Mounts, mt)
		if strings.EqualFold(mt.Type,"bind") && isDockerSocketPath(mt.Source) { m.DockerSocket=true }
	}
	for _, mount := range d.Mounts { appendMount(Mount{Type:mount.Type, Source:mount.Source, Target:mount.Destination, ReadOnly:!mount.RW}) }
	for _, bind := range d.HostConfig.Binds {
		parts:=strings.Split(bind,":"); if len(parts)<2 { continue }
		ro:=len(parts)>=3 && strings.Contains(strings.ToLower(parts[2]),"ro")
		appendMount(Mount{Type:"bind",Source:parts[0],Target:parts[1],ReadOnly:ro})
	}
	for _, device:=range d.HostConfig.Devices { m.Devices=append(m.Devices,DeviceMapping{HostPath:device.PathOnHost,ContainerPath:device.PathInContainer,Permissions:device.CgroupPermissions}) }
	for key:=range d.Config.ExposedPorts { var port int; if _,err:=fmt.Sscanf(key,"%d/",&port); err==nil&&port>0 { m.ExposedPorts=append(m.ExposedPorts,port) } }
	for _,env:=range d.Config.Env { if i:=strings.IndexByte(env,'='); i>0 { m.EnvKeys=append(m.EnvKeys,env[:i]) } }
	return m,nil
}

func resolveDockerUserSpec(user string) (runAsRoot bool, verified bool) {
	user = strings.TrimSpace(user)
	if user == "" || strings.EqualFold(user,"root") { return true,true }
	uid, err := strconv.ParseUint(user,10,32)
	if err != nil {
		// A named image user can resolve to UID 0 through /etc/passwd. Inspect JSON
		// alone cannot prove otherwise, so keep identity unresolved/fail-closed.
		return false,false
	}
	return uid==0,true
}

func isDockerSocketPath(path string) bool {
	path=strings.TrimSpace(path)
	return path=="/var/run/docker.sock" || path=="/run/docker.sock"
}
