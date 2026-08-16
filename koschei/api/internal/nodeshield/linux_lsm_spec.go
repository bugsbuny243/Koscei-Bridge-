//go:build linux

package nodeshield

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

// normalizeCgroupLSMSpec removes any dependency on the ELF reader knowing the
// newer lsm_cgroup/ section convention. cilium/ebpf v0.22.0 does not advertise
// that prefix in its public section table, while the kernel expects LSM
// programs loaded with BPF_LSM_CGROUP and the exact hook BTF target.
func normalizeCgroupLSMSpec(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return fmt.Errorf("nil LSM collection spec")
	}
	count := 0
	for name, prog := range spec.Programs {
		if prog == nil {
			return fmt.Errorf("nil program spec %q", name)
		}
		section := strings.TrimSpace(prog.SectionName)
		if !strings.HasPrefix(section, "lsm_cgroup/") {
			continue
		}
		hook := strings.TrimSpace(strings.TrimPrefix(section, "lsm_cgroup/"))
		if hook == "" || strings.Contains(hook, "/") {
			return fmt.Errorf("invalid cgroup LSM section %q", section)
		}
		prog.Type = ebpf.LSM
		prog.AttachType = ebpf.AttachLSMCgroup
		prog.AttachTo = hook
		count++
	}
	if count == 0 {
		return fmt.Errorf("LSM object contains no lsm_cgroup programs")
	}
	return nil
}
