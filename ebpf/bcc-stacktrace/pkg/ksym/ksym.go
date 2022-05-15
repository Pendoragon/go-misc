package ksym

import (
	"bufio"
	"log"
	"os"
	"strconv"
)

const UnresolvedSym string = "Unknown"

// Resolve kernel memory addresses to symbols. Notice that the addrs should be sorted
func ResolveAddrs(addrs []uint64) []string {
	if len(addrs) == 0 {
		return nil
	}
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		log.Printf("Failed to open /proc/kallsyms: %v", err)
	}
	defer f.Close()

	symbols := []string{}
	lastSymbol := UnresolvedSym
	scanner := bufio.NewScanner(f)

	log.Printf("Resolving kernel address: %+v", addrs)
	for scanner.Scan() {
		// Each line in /proc/kallsyms is formatted like the following:
		// ffffffff9d000000 T startup_64
		line := scanner.Bytes()
		addr, err := strconv.ParseUint(string(line[:16]), 16, 64)
		if err != nil {
			log.Printf("Failed to parse address for line %s", line)
		}
		for addr >= addrs[0] {
			log.Printf("Resolving kernel address %x to %s", addrs[0], lastSymbol)

			symbols = append(symbols, lastSymbol)
			addrs = addrs[1:]
			if len(addrs) == 0 {
				goto out
			}
		}
		// Parse symbol for current line
		lastSymbol = string(line[19:])
	}
	// The rest of the addresses should probably be resolved to the last symbol
	for i := 0; i < len(addrs); i++ {
		symbols = append(symbols, lastSymbol)
	}

out:
	// Print resolved symbols
	log.Println("Resolved symbols:")
	for i := range addrs {
		log.Printf("\t0x%x: \t%s", addrs[i], symbols[i])
	}
	return symbols
}
