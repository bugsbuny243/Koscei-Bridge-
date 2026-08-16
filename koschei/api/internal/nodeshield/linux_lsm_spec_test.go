//go:build linux

package nodeshield

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestNormalizeCgroupLSMSpec(t *testing.T) {
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"exec": {Name: "exec", SectionName: "lsm_cgroup/bprm_check_security"},
		"write": {Name: "write", SectionName: "lsm_cgroup/file_permission"},
	}}
	if err := normalizeCgroupLSMSpec(spec); err != nil {
		t.Fatal(err)
	}
	for name, prog := range spec.Programs {
		if prog.Type != ebpf.LSM {
			t.Fatalf("%s: expected LSM type, got %v", name, prog.Type)
		}
		if prog.AttachType != ebpf.AttachLSMCgroup {
			t.Fatalf("%s: expected AttachLSMCgroup, got %v", name, prog.AttachType)
		}
		if prog.AttachTo == "" {
			t.Fatalf("%s: expected hook BTF target", name)
		}
	}
}

func TestNormalizeCgroupLSMSpecRejectsMissingPrograms(t *testing.T) {
	if err := normalizeCgroupLSMSpec(&ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{}}); err == nil {
		t.Fatal("expected missing cgroup LSM programs to fail closed")
	}
}

func TestNormalizeCgroupLSMSpecRejectsMalformedHook(t *testing.T) {
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"bad": {Name: "bad", SectionName: "lsm_cgroup/a/b"},
	}}
	if err := normalizeCgroupLSMSpec(spec); err == nil {
		t.Fatal("expected malformed hook target to fail closed")
	}
}
