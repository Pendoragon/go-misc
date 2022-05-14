package profile_test

import (
	"os"
	"testing"

	"github.com/google/pprof/profile"
)

func TestProfile(t *testing.T) {
	// Create an empty new Profile we can start adding stuff to.
	p := profile.Profile{
		PeriodType: &profile.ValueType{
			Type: "cpu",
			Unit: "nanoseconds",
		},
		Period: 10000000,
	}

	// SampleType specifies what type the samples are of.
	// Usually shown in the top of the profile visualization.
	p.SampleType = []*profile.ValueType{{
		Type: "samples", // We want to have a profile that describes the allocations
		Unit: "count",       // in bytes.
	}}
	p.Function = []*profile.Function{{
		ID:         1,
		Name:       "func1",
		SystemName: "kernel",
		StartLine:  0,
	}, {
		ID:         2,
		Name:       "func2",
		SystemName: "kernel",
		StartLine:  22,
	}, {
		ID:         3,
		Name:       "func3",
		SystemName: "kernel",
		StartLine:  42,
	}, {
		ID:         4,
		Name:       "func4",
		SystemName: "kernel",
		StartLine:  42,
	}, {
		ID:         5,
		Name:       "func5",
		SystemName: "kernel",
		StartLine:  42,
	}, {
		ID:         6,
		Name:       "func6",
		SystemName: "kernel",
		StartLine:  42,
	}, {
		ID:         7,
		Name:       "func7",
		SystemName: "kernel",
		StartLine:  42,
	}}
	// Locations are addresses inside the processes memory.
	p.Location = []*profile.Location{{
		ID:      1,
		Address: 0xffffffff9da76ba9,
		Line: []profile.Line{{
			Function: p.Function[0],
			Line:     42,
		}},
	},{
		ID: 2,
		Address: 0xffffffff9d02f9c8,
		Line: []profile.Line{{
			Function: p.Function[1],
			Line:     20,
		}},
	},{
		ID: 3,
		Address: 0xffffffff9da76c33,
		Line: []profile.Line{{
			Function: p.Function[2],
			Line:     20,
		}},
	},{
		ID: 4,
		Address: 0xffffffff9d145bc2,
		Line: []profile.Line{{
			Function: p.Function[3],
			Line:     20,
		}},
	},{
		ID: 5,
		Address: 0xffffffff9d145e36,
		Line: []profile.Line{{
			Function: p.Function[4],
			Line:     20,
		}},
	},{
		ID: 6,
		Address: 0xffffffff9e9be085,
		Line: []profile.Line{{
			Function: p.Function[5],
			Line:     20,
		}},
	},{
		ID: 7,
		Address: 0xffffffff9d0000f5,
		Line: []profile.Line{{
			Function: p.Function[6],
			Line:     20,
		}},
	}}
	p.Sample = []*profile.Sample{{
		Location: []*profile.Location{p.Location[0]},
		Value:    []int64{10},
		// Says that the location allocated 128 bytes (because the first sample type is alloc_space).
	}, {
		Location: []*profile.Location{p.Location[4], p.Location[3], p.Location[2], p.Location[1]},
		Value:    []int64{10},
		// For demo purposes let's make this second function allocate 4 times as much.
	}, {
		Location: []*profile.Location{p.Location[5], p.Location[3], p.Location[2], p.Location[1]},
		Value:    []int64{10},
	}}
	// Create a new file to write the profile to.
	f, err := os.Create("profile.pb.gz")
	if err != nil {
		t.Fatal(err)
	}
	// Write the profile to the file.
	if err := p.Write(f); err != nil {
		t.Fatal(err)
	}
}
