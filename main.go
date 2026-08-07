// Command secretscan scans files for strings that are likely to be secrets.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ryankidd/secretscan/internal/scan"
)

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: secretscan <file>")
		os.Exit(2)
	}

	findings, err := scan.File(args[0], scan.DefaultOptions())
	if err != nil {
		fmt.Fprintln(os.Stderr, "secretscan:", err)
		os.Exit(1)
	}

	for _, f := range findings {
		fmt.Printf("%s:%d: possible secret (entropy %.2f): %s\n", f.Path, f.Line, f.Entropy, f.Token)
	}

	if len(findings) > 0 {
		os.Exit(1)
	}
}
