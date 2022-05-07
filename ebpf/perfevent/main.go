//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"flag"
	"log"
	"unsafe"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -cflags "-O2 -Wall -g -Werror -D__TARGET_ARCH_x86" bpf perfevent.c -- -I../headers

const TASK_COMM_LEN int = 16
const MAX_STACK_DEPTH int = 127

type countsMapKey struct {
	TaskComm  [TASK_COMM_LEN]byte
	KernStackId int32
	UserStackId int32
}

type callStack [MAX_STACK_DEPTH]uint64

func main() {
	target_pid := flag.Int("pid", -1, "PID of the process whose stack traces will be collected. Default to -1, i.e. all processes")
	flag.Parse()

		// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs:= bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading bpf objects: %v", err)
	}
	defer objs.Close()

	fd, err := unix.PerfEventOpen(
		&unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Sample: 100,
			Bits:   unix.PerfBitDisabled | unix.PerfBitFreq,
		},
		*target_pid,
		-1,
		-1,
		unix.PERF_FLAG_FD_CLOEXEC,
	)
	if err != nil {
		log.Fatalf("opening perf event: %v", err)
	}

	err = attachPerfEvent(fd, objs.BpfProg1)
	if err != nil {
		log.Fatalf("attaching perf event: %v", err)
	}

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		itCounts := objs.Counts.Iterate()
		var countsKey countsMapKey
		var countsValue uint64

		for itCounts.Next(&countsKey, &countsValue) {
			log.Println("==============================================================================================================")
			log.Printf("kernel stack id: %v; user stack id: %v; seen times: %d", countsKey.KernStackId, countsKey.UserStackId, countsValue)

			var userStack, kernStack callStack
			err := objs.Stackmap.Lookup(unsafe.Pointer(&countsKey.KernStackId), &kernStack)
			if err != nil {
				log.Printf("Failed to lookup kernel stack with id: %d, %v", countsKey.KernStackId, err)
			}

			err = objs.Stackmap.Lookup(unsafe.Pointer(&countsKey.UserStackId), &userStack)
			if err != nil {
				log.Printf("Failed to lookup user stack with id: %d, %v", countsKey.UserStackId, err)
			}

			// print stack
			for _, addr := range kernStack {
				if addr != uint64(0) {
					log.Printf("0x%x", addr)
				}
			}
			for _, addr := range userStack {
				if addr != uint64(0) {
					log.Printf("0x%x", addr)
				}
			}

			log.Println("==============================================================================================================")
		}
	}
}
