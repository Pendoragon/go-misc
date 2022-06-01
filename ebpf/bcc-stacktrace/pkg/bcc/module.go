package bcc

import (
	"fmt"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
	"golang.org/x/sys/unix"
	"github.com/iovisor/gobpf/pkg/cpuonline"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
*/
import "C"

type BPFModule struct {
	*bpf.Module
	perfEvents     []int
}

func NewModule(code string, cflags []string) *BPFModule {
	m := bpf.NewModule(code, cflags)
	module := &BPFModule{
		m,
		[]int{},
	}

	return module
}

func (m *BPFModule) Close() {
	for v := range m.perfEvents {
		C.bpf_close_perf_event_fd((C.int)(v))
	}

	m.Module.Close()
}

func (m *BPFModule) AttachPerfEventRaw(progfd int, attr *unix.PerfEventAttr, pid, cpu, groupFd int, extra_flags int) error {
	res := []int{}

	if cpu >= 0 {
		r, err := C.bpf_attach_perf_event_raw(C.int(progfd), unsafe.Pointer(attr), C.pid_t(pid), C.int(cpu), C.int(groupFd), C.ulong(extra_flags))
		if r < 0 {
			return fmt.Errorf("failed to attach BPF perf event: %v", err)
		}

		res = append(res, int(r))
	} else {
		cpus, err := cpuonline.Get()
		if err != nil {
			return fmt.Errorf("failed to determine online cpus: %v", err)
		}

		for _, i := range cpus {
			r, err := C.bpf_attach_perf_event_raw(C.int(progfd), unsafe.Pointer(attr), C.pid_t(pid), C.int(i), C.int(groupFd), C.ulong(extra_flags))
			if r < 0 {
				return fmt.Errorf("failed to attach BPF perf event: %v", err)
			}

			res = append(res, int(r))
		}
	}

	m.perfEvents = append(m.perfEvents, res...)

	return nil
}
