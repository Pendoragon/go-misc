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
	"fmt"
	"log"
	"os"
	"time"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/google/pprof/profile"
	unix "golang.org/x/sys/unix"
)

//go:embed stack_trace.c
var source string

const TASK_COMM_LEN int = 16
const MAX_STACK_DEPTH int = 127

// KernStackId/UserStackId can be nagative, e.g. -14 if stack not found
type countsMapKey struct {
	TaskComm    [TASK_COMM_LEN]byte
	Pid         uint32
	KernStackId int32
	UserStackId int32
}

type callStack [MAX_STACK_DEPTH]uint64

// TODO:
//   1. Add kernel/user symbol resolution
//   2. Create pprof data from stack trace
//   3. Change the observed entity from a single process to a container
func main() {
	target_pid := flag.Int("pid", -1, "PID of the process whose stack traces will be collected. Default to -1, i.e. all processes")
	duration := flag.Duration("duration", 5*time.Second, "Duration of the profiling. Default to 5s")
	flag.Parse()
	cflags := []string{}

	m := bpf.NewModule(source, cflags)
	defer m.Close()

	// Load the bpf program with type BPF_PROG_TYPE_PERF_EVENT
	fd, err := m.LoadPerfEvent("bpf_prog1")
	if err != nil {
		log.Fatalf("Failed to load bpf_prog1: %v\n", err)
	}

	// Open a perf event of type PERF_TYPE_SOFTWARE, setting sample rate to 100Hz(i.e. 100 samples/s) for process with target_pid
	// on any CPU. And attach the bpf program to it.
	err = m.AttachPerfEvent(unix.PERF_TYPE_SOFTWARE, unix.PERF_COUNT_SW_CPU_CLOCK, 0, 100, *target_pid, -1, -1, fd)
	if err != nil {
		log.Fatalf("Failed to attach to perf event: %v\n", err)
	}

	countsTable := bpf.NewTable(m.TableId("counts"), m)
	stackmapTable := bpf.NewTable(m.TableId("stackmap"), m)

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(*duration)
	defer ticker.Stop()

	for range ticker.C {
		itCounts := countsTable.Iter()
		var countsKeyBytes, countsValueBytes []byte
		var countsKey countsMapKey
		var countsValue uint64
		samplesMap := map[[2]callStack]*profile.Sample{}
		locations := []*profile.Location{}
		// Map {Pid, Address} => ID of location. Userspace address for different process can overlap
		locationIdMap := map[[2]uint64]int{}

		// Each entry in counts map is a sample in pprof
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

			log.Println("==============================================================================================================")
			log.Printf("kernel stack id: %v; user stack id: %v; seen times: %d", countsKey.KernStackId, countsKey.UserStackId, countsValue)

			var userStackBytes, kernStackBytes []byte
			var userStack, kernStack callStack

			bs := make([]byte, 4)
			binary.LittleEndian.PutUint32(bs, uint32(countsKey.KernStackId))
			kernStackBytes, err = stackmapTable.Get(bs)
			if err != nil {
				log.Printf("Failed to lookup kernel stack with id: %d, %v", countsKey.KernStackId, err)
			} else {
				err = binary.Read(bytes.NewBuffer(kernStackBytes), binary.LittleEndian, &kernStack)
				if err != nil {
					log.Printf("decoding kernel stack: %v", countsKey.KernStackId)
				}
			}

			binary.LittleEndian.PutUint32(bs, uint32(countsKey.UserStackId))
			userStackBytes, err = stackmapTable.Get(bs)
			if err != nil {
				log.Printf("Failed to lookup user stack with id: %d, %v", countsKey.UserStackId, err)
			} else {
				err = binary.Read(bytes.NewBuffer(userStackBytes), binary.LittleEndian, &userStack)
				if err != nil {
					log.Printf("decoding user stack: %v", countsKey.UserStackId)
				}
			}

			sampleKey := [2]callStack{
				kernStack,
				userStack,
			}
			// If we've seen the stack trace with different stack id, simply add to sample value
			s, ok := samplesMap[sampleKey]
			if ok {
				s.Value[0] += int64(countsValue)
				continue
			}

			// Build sample locations
			sampleLocations := []*profile.Location{}
			for _, addr := range kernStack {
				if addr != uint64(0) {
					idKey := [2]uint64{
						uint64(0),
						addr,
					}
					id, ok := locationIdMap[idKey]
					if !ok {
						id = len(locationIdMap)
						l := &profile.Location{
							ID: uint64(id + 1),
							Address: addr,
						}
						locationIdMap[idKey] = id
						locations = append(locations, l)
					}
					sampleLocations = append(sampleLocations, locations[id])
				}
			}
			for _, addr := range userStack {
				if addr != uint64(0) {
					idKey := [2]uint64{
						uint64(countsKey.Pid),
						addr,
					}
					id, ok := locationIdMap[idKey]
					if !ok {
						id = len(locationIdMap)
						l := &profile.Location{
							ID: uint64(id + 1),
							Address: addr,
						}
						locationIdMap[idKey] = id
						locations = append(locations, l)
					}
					sampleLocations = append(sampleLocations, locations[id])
				}
			}

			sample := &profile.Sample{
				Location: sampleLocations,
				Value: []int64{int64(countsValue)},
			}
			samplesMap[sampleKey] = sample
			// print stack
			log.Println("Kernel stack:")
			for _, addr := range kernStack {
				if addr != uint64(0) {
					log.Printf("\t0x%x", addr)
				}
			}
			log.Println("User stack:")
			for _, addr := range userStack {
				if addr != uint64(0) {
					log.Printf("\t0x%x", addr)
				}
			}
			log.Printf("%+v", sample)
			log.Println("==============================================================================================================")
		}
		var samples []*profile.Sample
		for _, s := range samplesMap {
			samples = append(samples, s)
		}
		// Build profile and write to pprof file
		p := profile.Profile{
			PeriodType: &profile.ValueType{
				Type: "cpu",
				Unit: "nanoseconds",
			},
			Period: 10000000,
			SampleType: []*profile.ValueType{
				{
					Type: "samples",
					Unit: "count",
				},
			},
			Sample: samples,
			Location: locations,
			Function: []*profile.Function{},
		}
		log.Printf("%+v", p)
		// Add lines to locations
		for _, l := range p.Location {
			function := &profile.Function{
				ID: uint64(len(p.Function) + 1),
				Name: fmt.Sprintf("0x%x", l.Address),
			}
			p.Function = append(p.Function, function)
			l.Line = []profile.Line{
				{
					Function: function,
				},
			}
		}
		// Create a new file to write the profile to.
		pprofFileName := fmt.Sprintf("profile.pb.gz-%s", time.Now().Format("20060102150405"))
		f, err := os.Create(pprofFileName)
		if err != nil {
			log.Printf("Creating pprof file: %v", err)
		}
		// Write the profile to the file.
		if err := p.Write(f); err != nil {
			log.Printf("Writing to pprof file: %v", err)
		}
	}
}
