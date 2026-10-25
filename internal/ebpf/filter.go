package ebpf

import (
	"errors"
	"fmt"
	"runtime"
)

// KernelFilter is a placeholder for a future cgroup/connect4 egress filter.
type KernelFilter struct {
	Enabled   bool
	CgroupDir string
}

// AttachEgressFilter refuses to start when eBPF enforcement is requested but
// unavailable. Returning a fake success here would give operators a false
// sense of kernel-level containment.
func AttachEgressFilter(enabled bool, cgroupPath string) (*KernelFilter, error) {
	if !enabled {
		return &KernelFilter{Enabled: false}, nil
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("eBPF socket filtering requires Linux")
	}
	return nil, errors.New("eBPF enforcement is not implemented in this build; remove --ebpf or build a kernel-filter-enabled release")
}

// Close detaches the filter. It is a no-op when eBPF is disabled.
func (k *KernelFilter) Close() {
	if k == nil || !k.Enabled {
		return
	}
}
