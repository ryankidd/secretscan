package scan

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DefaultIgnore lists patterns that Dir skips by default. Entries ending in
// "/" match directories only, and patterns are matched against both a
// file or directory's base name and its path relative to the scan root.
var DefaultIgnore = []string{
	".git/",
	"node_modules/",
	"vendor/",
}

// binarySniffLen is the number of bytes read from the start of a file to
// decide whether it looks like binary data.
const binarySniffLen = 8000

// Dir recursively scans every regular file under root, skipping directories
// and files that match a default or user-supplied ignore pattern, as well
// as files that look like binary data.
func Dir(root string, opts Options) ([]Finding, error) {
	ignore := make([]string, 0, len(DefaultIgnore)+len(opts.Ignore))
	ignore = append(ignore, DefaultIgnore...)
	ignore = append(ignore, opts.Ignore...)

	var findings []Finding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}

		if d.IsDir() {
			if path != root && matchesIgnore(ignore, d.Name(), rel, true) {
				return filepath.SkipDir
			}
			return nil
		}

		if !d.Type().IsRegular() || matchesIgnore(ignore, d.Name(), rel, false) {
			return nil
		}

		binary, err := isBinary(path)
		if err != nil {
			return err
		}
		if binary {
			return nil
		}

		fileFindings, err := File(path, opts)
		if err != nil {
			return err
		}
		findings = append(findings, fileFindings...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}

	return findings, nil
}

// matchesIgnore reports whether name or rel matches any of the given
// gitignore-style patterns. A pattern ending in "/" only matches
// directories.
func matchesIgnore(patterns []string, name, rel string, isDir bool) bool {
	for _, p := range patterns {
		dirOnly := strings.HasSuffix(p, "/")
		pat := strings.TrimSuffix(p, "/")
		if dirOnly && !isDir {
			continue
		}

		if ok, _ := filepath.Match(pat, name); ok {
			return true
		}
		if ok, _ := filepath.Match(pat, rel); ok {
			return true
		}
	}
	return false
}

// isBinary reports whether the file at path looks like binary data, using
// the same heuristic as git and most other tools: the presence of a NUL
// byte within the first portion of the file.
func isBinary(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("scan: %w", err)
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, binarySniffLen)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return false, fmt.Errorf("scan: %w", err)
	}

	return bytes.IndexByte(buf[:n], 0) != -1, nil
}
