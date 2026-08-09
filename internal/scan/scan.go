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
	Path string
	Line int
	// Token is the matched text: the full regex match for pattern-based
	// detectors, or the flagged token for entropy-based findings.
	Token string
	// Detector names which Detector produced this finding, or "entropy"
	// for entropy-based findings.
	Detector string
	// Entropy is the Shannon entropy of Token, in bits per character.
	// Zero for pattern-based findings.
	Entropy float64
	// Commit is the commit hash that introduced Token, set only by
	// GitHistory. Empty for File and Dir findings.
	Commit string
}

// Options controls scan behavior.
type Options struct {
	EntropyThreshold float64
	MinLength        int
	// Ignore lists additional gitignore-style patterns for Dir to skip, on
	// top of DefaultIgnore. Unused by File.
	Ignore []string
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
	defer func() { _ = f.Close() }()

	var findings []Finding
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		for _, m := range findMatches(scanner.Text(), opts) {
			m.Path = path
			m.Line = lineNum
			findings = append(findings, m)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}

	return findings, nil
}

// findMatches runs the pattern-based and entropy-based detectors against a
// single line, returning a Finding per match with Path, Line, and Commit
// left for the caller to fill in.
func findMatches(line string, opts Options) []Finding {
	var findings []Finding

	for _, d := range Detectors {
		for _, match := range d.Pattern.FindAllString(line, -1) {
			findings = append(findings, Finding{
				Token:    match,
				Detector: d.Name,
			})
		}
	}

	for _, token := range strings.Fields(line) {
		token = strings.Trim(token, trimSet)
		if len(token) < opts.MinLength {
			continue
		}

		entropy := ShannonEntropy(token)
		if entropy < opts.EntropyThreshold {
			continue
		}

		findings = append(findings, Finding{
			Token:    token,
			Detector: "entropy",
			Entropy:  entropy,
		})
	}

	return findings
}
