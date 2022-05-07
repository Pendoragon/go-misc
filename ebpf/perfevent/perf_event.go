package main

import (
	"fmt"
	"errors"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func attachPerfEvent(pefd int, prog *ebpf.Program) error {
	if prog == nil {
		return errors.New("cannot attach a nil program")
	}
	if prog.FD() < 0 {
		return fmt.Errorf("invalid program: %w")
	}

	// if err := haveBPFLinkPerfEvent(); err == nil {
	// 	return attachPerfEventLink(pe, prog)
	// }
	return attachPerfEventIoctl(pefd, prog)
}

func attachPerfEventIoctl(pefd int, prog *ebpf.Program) error {
	fmt.Printf("attaching prog fd %v to perf event fd %v", prog.FD(), pefd)
	// Assign the eBPF program to the perf event.
	err := unix.IoctlSetInt(pefd, unix.PERF_EVENT_IOC_SET_BPF, prog.FD())
	if err != nil {
		return fmt.Errorf("setting perf event bpf program: %w", err)
	}

	// PERF_EVENT_IOC_ENABLE and _DISABLE ignore their given values.
	if err := unix.IoctlSetInt(pefd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		return fmt.Errorf("enable perf event: %s", err)
	}
	return nil
}
