// Command secretscan scans files for strings that are likely to be secrets.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ryankidd/secretscan/internal/scan"
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
	flag.Var(&ignore, "ignore", "glob pattern to skip when scanning a directory (repeatable); suffix with / to match directories only")
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: secretscan [-ignore pattern] <file|directory>")
		os.Exit(2)
	}

	opts := scan.DefaultOptions()
	opts.Ignore = ignore

	info, err := os.Stat(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "secretscan:", err)
		os.Exit(1)
	}

	var findings []scan.Finding
	if info.IsDir() {
		findings, err = scan.Dir(args[0], opts)
	} else {
		findings, err = scan.File(args[0], opts)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "secretscan:", err)
		os.Exit(1)
	}

	for _, f := range findings {
		if f.Detector == "entropy" {
			fmt.Printf("%s:%d: possible secret (entropy %.2f): %s\n", f.Path, f.Line, f.Entropy, f.Token)
		} else {
			fmt.Printf("%s:%d: possible secret (%s): %s\n", f.Path, f.Line, f.Detector, f.Token)
		}
	}

	if len(findings) > 0 {
		os.Exit(1)
	}
}
