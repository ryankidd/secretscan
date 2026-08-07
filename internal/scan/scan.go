// Package scan finds strings that are likely to be secrets.
package scan

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// DefaultEntropyThreshold is the minimum Shannon entropy, in bits per
// character, for a token to be flagged as a possible secret.
const DefaultEntropyThreshold = 4.0

// DefaultMinLength is the shortest token considered for entropy scanning.
// Short tokens don't carry enough characters for entropy to be a reliable
// signal.
const DefaultMinLength = 20

// trimSet holds punctuation commonly wrapped around tokens (quotes,
// separators, brackets) that isn't part of the token itself.
const trimSet = "\"'`,;:(){}[]<>"

// Finding is a single possible secret found in a file.
type Finding struct {
	Path    string
	Line    int
	Token   string
	Entropy float64
}

// Options controls scan behavior.
type Options struct {
	EntropyThreshold float64
	MinLength        int
}

// DefaultOptions returns the default scan Options.
func DefaultOptions() Options {
	return Options{
		EntropyThreshold: DefaultEntropyThreshold,
		MinLength:        DefaultMinLength,
	}
}

// File scans a single file line by line for high-entropy tokens.
func File(path string, opts Options) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	defer f.Close()

	var findings []Finding
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		for _, token := range strings.Fields(scanner.Text()) {
			token = strings.Trim(token, trimSet)
			if len(token) < opts.MinLength {
				continue
			}

			entropy := ShannonEntropy(token)
			if entropy < opts.EntropyThreshold {
				continue
			}

			findings = append(findings, Finding{
				Path:    path,
				Line:    lineNum,
				Token:   token,
				Entropy: entropy,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}

	return findings, nil
}
