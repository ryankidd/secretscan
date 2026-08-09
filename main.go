// Command secretscan scans files for strings that are likely to be secrets.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ryankidd/secretscan/internal/scan"
)

// Exit codes distinguish "the scan ran and found something" from "the scan
// itself failed," so a CI step can tell the two apart.
const (
	exitClean    = 0
	exitFindings = 1
	exitError    = 2
)

// ignoreList collects repeated -ignore flag values into a slice.
type ignoreList []string

func (i *ignoreList) String() string {
	return strings.Join(*i, ",")
}

func (i *ignoreList) Set(v string) error {
	*i = append(*i, v)
	return nil
}

func main() {
	var ignore ignoreList
	var history bool
	var format string
	flag.Var(&ignore, "ignore", "glob pattern to skip when scanning a directory (repeatable); suffix with / to match directories only")
	flag.BoolVar(&history, "history", false, "scan git commit history instead of the working tree; the argument is a path to a git repository")
	flag.StringVar(&format, "format", "text", "output format: text or json")
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: secretscan [-ignore pattern] [-history] [-format text|json] <file|directory>")
		os.Exit(exitError)
	}
	if format != "text" && format != "json" {
		fmt.Fprintf(os.Stderr, "secretscan: unknown format %q\n", format)
		os.Exit(exitError)
	}

	opts := scan.DefaultOptions()
	opts.Ignore = ignore

	var findings []scan.Finding
	var err error
	if history {
		findings, err = scan.GitHistory(args[0], opts)
	} else {
		var info os.FileInfo
		info, err = os.Stat(args[0])
		if err == nil {
			if info.IsDir() {
				findings, err = scan.Dir(args[0], opts)
			} else {
				findings, err = scan.File(args[0], opts)
			}
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "secretscan:", err)
		os.Exit(exitError)
	}

	if format == "json" {
		printJSON(findings)
	} else {
		printText(findings)
	}

	if len(findings) > 0 {
		os.Exit(exitFindings)
	}
	os.Exit(exitClean)
}

// printText writes findings in the default human-readable format.
func printText(findings []scan.Finding) {
	for _, f := range findings {
		loc := fmt.Sprintf("%s:%d", f.Path, f.Line)
		if f.Commit != "" {
			loc = fmt.Sprintf("%s@%s:%d", f.Path, f.Commit[:7], f.Line)
		}

		if f.Detector == "entropy" {
			fmt.Printf("%s: possible secret (entropy %.2f): %s\n", loc, f.Entropy, f.Token)
		} else {
			fmt.Printf("%s: possible secret (%s): %s\n", loc, f.Detector, f.Token)
		}
	}
}

// printJSON writes findings as a JSON array, for machine consumption.
func printJSON(findings []scan.Finding) {
	if findings == nil {
		findings = []scan.Finding{}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(findings); err != nil {
		fmt.Fprintln(os.Stderr, "secretscan:", err)
		os.Exit(exitError)
	}
}
