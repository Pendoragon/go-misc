//+build linux
package symbol

import(
	"debug/elf"
	"debug/gosym"
	"errors"
	"fmt"
)

// TODO:
// 1. support PIE elf which has no gopclntab
// 2. handle non-go symbols
func ResolveGoSyms(pid uint32, addrs []uint64) []string {
	res := []string{}
	foundTab := false
	var table *gosym.Table
	elfpath := fmt.Sprintf("/proc/%d/exe", pid)
	data, err := gopclntab(elfpath)
	if err != nil {
		fmt.Printf("Failed to read gopclntab: %v", err)
	}

	// try gopclntab for non-PIE elf
	if data != nil {
		table, err = gosym.NewTable(nil, gosym.NewLineTable(data, 0))
		if err != nil {
			fmt.Printf("gosym.NewTable: %w", err)
		} else {
			foundTab = true
		}
	}

	for _, addr := range addrs {
		if foundTab {
			res = append(res, resolveSymbol(table, addr))
		} else {
			// not resolvable via pclntab
			res = append(res, fmt.Sprintf("0x%x", addr))
		}
	}
	return res
}

func resolveSymbol(table *gosym.Table, pc uint64) string {
	file, line, fn := table.PCToLine(pc)
	fmt.Printf("%x: %s() %s:%d\n", pc, fn.Name, file, line)
	return fn.Name
}

func gopclntab(path string) ([]byte, error) {
	file, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("elf.Open: %w", err)
	}
	for _, s := range file.Sections {
		if s.Name == ".gopclntab" {
			return s.Data()
		}
	}
	return nil, errors.New("could not find .gopclntab")
}
