package main

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/go-ego/mingo/dict"
)

func main() {
	// Load the Thrift IDL file
	content, err := ioutil.ReadFile("example.thrift")
	if err != nil {
		panic(err)
	}

	// Parse the Thrift IDL file and extract the identifiers
	program, err := thrift.Parse(string(content))
	if err != nil {
		panic(err)
	}

	var identifiers []string
	for _, definition := range program.Definitions {
		switch def := definition.(type) {
		case *thrift.StructDefinition:
			identifiers = append(identifiers, def.Name)
			for _, field := range def.Fields {
				identifiers = append(identifiers, field.Name)
			}
		case *thrift.ServiceDefinition:
			identifiers = append(identifiers, def.Name)
			for _, function := range def.Functions {
				identifiers = append(identifiers, function.Name)
			}
		}
	}

	// Check the spelling and camel case of the extracted identifiers
	spellingDict := dict.New()
	misspelledIdentifiers := []string{}
	nonCamelCaseIdentifiers := []string{}
	for _, identifier := range identifiers {
		if !spellingDict.Has(identifier) {
			misspelledIdentifiers = append(misspelledIdentifiers, identifier)
		}
		if !isCamelCase(identifier) {
			nonCamelCaseIdentifiers = append(nonCamelCaseIdentifiers, identifier)
		}
	}

	// Generate a report of any issues
	if len(misspelledIdentifiers) > 0 || len(nonCamelCaseIdentifiers) > 0 {
		report := "Linting issues found:\n"
		if len(misspelledIdentifiers) > 0 {
			report += fmt.Sprintf("Misspelled identifiers: %s\n", strings.Join(misspelledIdentifiers, ", "))
		}
		if len(nonCamelCaseIdentifiers) > 0 {
			report += fmt.Sprintf("Non-camel case identifiers: %s\n", strings.Join(nonCamelCaseIdentifiers, ", "))
		}
		fmt.Println(report)
	} else {
		fmt.Println("No linting issues found.")
	}
}

func isCamelCase(str string) bool {
	if len(str) == 0 || !isLetter(str[0]) {
		return false
	}

	pattern := "^[a-zA-Z][a-zA-Z0-9]*$"
	match, _ := regexp.MatchString(pattern, str)
	return match
}

func isLetter(char byte) bool {
	return ('a' <= char && char <= 'z') || ('A' <= char && char <= 'Z')
}
