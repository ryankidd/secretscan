package scan

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// commitSep separates commit records in the git log output below. It's a
// control character that won't appear in a text diff and, unlike NUL,
// isn't rejected inside an argv string.
const commitSep = "\x01"

// GitHistory scans every commit in the git repository at repoPath, checking
// the lines each commit adds against the same detectors File uses.
// Findings report the commit that introduced the line, so a secret that
// was later removed still turns up.
func GitHistory(repoPath string, opts Options) ([]Finding, error) {
	cmd := exec.Command("git", "-C", repoPath, "log", "--root", "--no-color", "-p", "--unified=3", "--pretty=format:"+commitSep+"%H")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("scan: git log: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	var findings []Finding
	for _, record := range strings.Split(string(out), commitSep) {
		if record == "" {
			continue
		}

		hash, diff, _ := strings.Cut(record, "\n")
		findings = append(findings, scanDiff(hash, diff, opts)...)
	}

	return findings, nil
}

// scanDiff runs the line-based detectors over the lines a single commit's
// diff adds, associating each match with the file and line it appears at
// in that commit's version of the file.
func scanDiff(hash, diff string, opts Options) []Finding {
	var findings []Finding
	var path string
	var newLine int

	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "+++ "):
			path = strings.TrimPrefix(strings.TrimPrefix(line, "+++ "), "b/")
		case strings.HasPrefix(line, "@@ "):
			newLine = hunkNewStart(line)
		case strings.HasPrefix(line, "+"):
			for _, m := range findMatches(strings.TrimPrefix(line, "+"), opts) {
				m.Path = path
				m.Line = newLine
				m.Commit = hash
				findings = append(findings, m)
			}
			newLine++
		case strings.HasPrefix(line, "-"):
			// A deletion doesn't exist in the new file, so it doesn't
			// advance the new-file line counter.
		case strings.HasPrefix(line, `\ No newline at end of file`):
			// Not a line of the file, just a diff annotation.
		default:
			// Context line: present in both old and new files.
			newLine++
		}
	}

	return findings
}

// hunkNewStart parses the starting line number of the new-file side of a
// unified diff hunk header, e.g. "@@ -12,3 +15,4 @@ func foo() {".
func hunkNewStart(header string) int {
	_, after, ok := strings.Cut(header, "+")
	if !ok {
		return 0
	}
	numPart, _, _ := strings.Cut(after, ",")
	numPart, _, _ = strings.Cut(numPart, " ")

	n, err := strconv.Atoi(numPart)
	if err != nil {
		return 0
	}
	return n
}
