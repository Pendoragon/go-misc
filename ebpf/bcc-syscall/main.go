//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"flag"
	"log"
	"time"

	bpf "github.com/iovisor/gobpf/bcc"
)

//go:embed syscall_count_adv.c
var source string

type countsMapKey struct {
	Pid         uint32
  TimeStamp   uint64
}

func main() {
	syscall := flag.String("syscall", "", "Name of the syscall")
	duration := flag.Duration("interval", 2*time.Second, "Interval. Default to 2s")
	flag.Parse()

	cflags := []string{}
	m := bpf.NewModule(source, cflags)
	defer m.Close()

	// Load the bpf program with type BPF_PROG_TYPE_PERF_EVENT
	fd, err := m.LoadKprobe("syscall__probe_counter")
	if err != nil {
		log.Fatalf("Failed to load syscall__probe_counter: %v\n", err)
	}

	fn := bpf.GetSyscallFnName(*syscall)
	log.Printf("tracing syscall: %s", fn)
	m.AttachKprobe(fn, fd, -1)

	countsTable := bpf.NewTable(m.TableId("counts_by_pid_ts"), m)

	// Read, process and clean counts/stackmap table
	ticker := time.NewTicker(*duration)
	defer ticker.Stop()

	for range ticker.C {
		log.Println("==============================================================================================================")
		itCounts := countsTable.Iter()
		var countsKeyBytes, countsValueBytes []byte
		var countsKey countsMapKey
		var countsValue uint64
		for itCounts.Next() {
			countsKeyBytes = itCounts.Key()
			countsValueBytes = itCounts.Leaf()
			err := binary.Read(bytes.NewBuffer(countsKeyBytes), binary.LittleEndian, &countsKey)
			if err != nil {
				log.Printf("decoding counts map key: %v", countsKey)
			}
			err = binary.Read(bytes.NewBuffer(countsValueBytes), binary.LittleEndian, &countsValue)
			if err != nil {
				log.Printf("decoding counts map value: %v", countsKey)
			}

			log.Printf("%v\t%v", countsKey, countsValue)
		}
		log.Println("==============================================================================================================")
	}
}
