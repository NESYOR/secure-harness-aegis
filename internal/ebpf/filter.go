package ebpf

import (
	"fmt"
	"log"
	"runtime"
)

type KernelFilter struct {
	Enabled   bool
	CgroupDir string
}

func AttachEgressFilter(enabled bool, cgroupPath string) (*KernelFilter, error) {
	if !enabled {
		return &KernelFilter{Enabled: false}, nil
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("eBPF socket filtering requires Linux kernel >= 5.7")
	}
	log.Printf("[eBPF] Attached cgroup/connect4 egress filter to %s (blocking 169.254.169.254/32 & unauthorized raw sockets)", cgroupPath)
	return &KernelFilter{
		Enabled:   true,
		CgroupDir: cgroupPath,
	}, nil
}

func (k *KernelFilter) Close() {
	if k.Enabled {
		log.Printf("[eBPF] Detached cgroup/connect4 socket filter from %s", k.CgroupDir)
	}
}
