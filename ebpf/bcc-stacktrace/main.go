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
	"runtime"
	"sort"
	"time"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
	bcc "github.com/pendoragon/code/ebpf/bcc-stacktrace/pkg/bcc"
	"github.com/google/pprof/profile"
	"github.com/pendoragon/code/ebpf/bcc-stacktrace/pkg/ksym"
	"golang.org/x/sys/unix"
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
//   1. Add user symbol resolution
func main() {
	target_pid := flag.Int("pid", -1, "PID of the process whose stack traces will be collected. Default to -1, i.e. all processes")
	duration := flag.Duration("duration", 5*time.Second, "Duration of the profiling. Default to 5s")
	cgroupDir := flag.String("cgroup", "", "Cgroup directory")
	flag.Parse()

	extraFlags := 0
	target := *target_pid

	if *cgroupDir != "" {
		cgroup, err := os.Open(*cgroupDir)
		if err != nil {
			log.Fatalf("Failed to open cgroup directory %s: %v", *cgroupDir, err)
		}
		target = int(cgroup.Fd())
		extraFlags |= unix.PERF_FLAG_PID_CGROUP
	}
	cflags := []string{}

	m := bcc.NewModule(source, cflags)
	defer m.Close()

	// Load the bpf program with type BPF_PROG_TYPE_PERF_EVENT
	fd, err := m.LoadPerfEvent("bpf_prog1")
	if err != nil {
		log.Fatalf("Failed to load bpf_prog1: %v\n", err)
	}

	// Open a perf event of type PERF_TYPE_SOFTWARE, setting sample rate to 100Hz(i.e. 100 samples/s) for process with target_pid
	// on any CPU. And attach the bpf program to it.
	cpus := runtime.NumCPU()
	for i := 0; i < cpus; i++ {
		attr := &unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Sample: 100,
			Bits:   unix.PerfBitDisabled | unix.PerfBitFreq,
		}
		err = m.AttachPerfEventRaw(fd, attr, target, i, -1, extraFlags)
		if err != nil {
			log.Fatalf("Failed to attach to perf event: %v\n", err)
		}
	}

	countsTable := bpf.NewTable(m.Module.TableId("counts"), m.Module)
	stackmapTable := bpf.NewTable(m.Module.TableId("stackmap"), m.Module)

	// Read, process and clean counts/stackmap table
	ticker := time.NewTicker(*duration)
	defer ticker.Stop()

	for range ticker.C {
		itCounts := countsTable.Iter()
		var countsKeyBytes, countsValueBytes []byte
		var countsKey countsMapKey
		var countsValue uint64
		// It is possible that we see same call stack with different stackId, because stackId is
		// not derived from call stack alone. It is also possible that different processes have the
		// exact same call stack.
		pSamples := map[uint32]map[[2]callStack]*profile.Sample{}
		// Map from pid to locations, functions and location Ids
		pLocations := map[uint32][]*profile.Location{}
		pFunctions := map[uint32][]*profile.Function{}
		pLocationIds := map[uint32]map[uint64]int{}

		// Each entry in counts map is a sample in pprof
		for itCounts.Next() {
			// parse entries from bpf maps
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

			// Get data per process
			locations, ok := pLocations[countsKey.Pid]
			if !ok {
				locations = []*profile.Location{}
			}
			functions, ok := pFunctions[countsKey.Pid]
			if !ok {
				functions = []*profile.Function{}
			}
			samplesMap, ok := pSamples[countsKey.Pid]
			if !ok {
				samplesMap = map[[2]callStack]*profile.Sample{}
			}
			locationIdMap, ok := pLocationIds[countsKey.Pid]
			if !ok {
				locationIdMap = map[uint64]int{}
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
			var kernAddrs []uint64
			sampleLocations := []*profile.Location{}
			for _, addr := range kernStack {
				if addr != uint64(0) {
					id, ok := locationIdMap[addr]
					if !ok {
						id = len(locationIdMap)
						l := &profile.Location{
							ID: uint64(id + 1),
							Address: addr,
						}
						locationIdMap[addr] = id
						locations = append(locations, l)
						kernAddrs = append(kernAddrs, addr)
					}
					sampleLocations = append(sampleLocations, locations[id])
				}
			}
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

			// Sort kernel address for symbol resolution
			sort.Slice(kernAddrs, func(i, j int) bool { return kernAddrs[i] < kernAddrs[j] })
			syms := ksym.ResolveAddrs(kernAddrs)
			for i, addr := range kernAddrs {
				index, ok := locationIdMap[addr]
				// Address is successfully resolved
				if ok {
					log.Printf("Adding function with: 0x%x\t%s", addr, syms[i])
					f := &profile.Function{
						ID: uint64(len(functions) + 1),
						Name: syms[i],
						SystemName: "kernel",
					}
					// Assuming no duplicate functions
					functions = append(functions, f)
					locations[index].Line = []profile.Line{
						{
							Function: f,
						},
					}
				}
			}

			for _, addr := range userStack {
				if addr != uint64(0) {
					id, ok := locationIdMap[addr]
					if !ok {
						id = len(locationIdMap)
						// TODO: try to resolve user stack symbols
						f := &profile.Function{
							ID: uint64(len(functions) + 1),
							Name: fmt.Sprintf("0x%x", addr),
							SystemName: "User",
						}
					  functions = append(functions, f)
						l := &profile.Location{
							ID: uint64(id + 1),
							Address: addr,
							Line: []profile.Line{
								{
									Function: f,
								},
							},
						}
						locationIdMap[addr] = id
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
			log.Printf("%+v", sample)
			log.Println("==============================================================================================================")

			pLocations[countsKey.Pid] = locations
			pFunctions[countsKey.Pid] = functions
			pSamples[countsKey.Pid] = samplesMap
			pLocationIds[countsKey.Pid] = locationIdMap
		}
		// Clean the bpf tables
		err = countsTable.DeleteAll()
		if err != nil {
			log.Printf("Failed to clean counts table: %v", err)
		}
		err = stackmapTable.DeleteAll()
		if err != nil {
			log.Printf("Failed to clean stackmap table: %v", err)
		}

		for pid, samplesMap := range pSamples {
			// Build profile and write to pprof file
			var samples []*profile.Sample
			for _, s := range samplesMap {
				samples = append(samples, s)
			}

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
				Location: pLocations[pid],
				Function: pFunctions[pid],
			}
			log.Printf("%+v", p)

			pprofFileName := fmt.Sprintf("profile.pb.gz-%d-%s", pid, time.Now().Format("20060102150405"))
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
}
