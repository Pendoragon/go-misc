package main

import (
	"debug/gosym"
	"flag"
	"fmt"
	"log"
	"strconv"
)

func main() {
	path := flag.String("path", "", "Absolute path to golang binary")
	addr := flag.String("addr", "", "Address to be resolved")
	flag.Parse()

	data, err := gopclntab(*path)
	if err != nil {
		log.Fatalf("Failed to read gopclntab: %v", err)
	}

	pc, err := strconv.ParseUint(*addr, 16, 64)
	if err != nil {
		log.Fatalf("Failed to parse addr: %v", err)
	}
	err = resolveSymbol(data, pc)
	if err != nil {
		log.Fatalf("Failed to resolve symbols: %v", err)
	}
}

func resolveSymbol(gopclntab []byte, pc uint64) error {
	table, err := gosym.NewTable(nil, gosym.NewLineTable(gopclntab, 0))
	if err != nil {
		return fmt.Errorf("gosym.NewTable: %w", err)
	}

	file, line, fn := table.PCToLine(pc)
	fmt.Printf("%x: %s() %s:%d\n", pc, fn.Name, file, line)
	return nil
}
