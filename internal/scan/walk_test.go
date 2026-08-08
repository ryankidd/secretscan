package scan

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTreeFile creates path (and any parent directories) under dir with
// the given content.
func writeTreeFile(t *testing.T, dir, path, content string) {
	t.Helper()
	full := filepath.Join(dir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

const secretLine = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"

func TestDirWalksNestedDirectories(t *testing.T) {
	dir := t.TempDir()
	writeTreeFile(t, dir, "top.txt", secretLine)
	writeTreeFile(t, dir, "a/b/c/nested.txt", secretLine)

	findings, err := Dir(dir, DefaultOptions())
	if err != nil {
		t.Fatalf("Dir: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2: %+v", len(findings), findings)
	}
}

func TestDirAppliesDefaultIgnore(t *testing.T) {
	dir := t.TempDir()
	writeTreeFile(t, dir, "clean.txt", "nothing interesting here\n")
	writeTreeFile(t, dir, ".git/config", secretLine)
	writeTreeFile(t, dir, "node_modules/pkg/index.js", secretLine)
	writeTreeFile(t, dir, "vendor/lib/lib.go", secretLine)

	findings, err := Dir(dir, DefaultOptions())
	if err != nil {
		t.Fatalf("Dir: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0: %+v", len(findings), findings)
	}
}

func TestDirAppliesUserIgnore(t *testing.T) {
	dir := t.TempDir()
	writeTreeFile(t, dir, "keep.txt", secretLine)
	writeTreeFile(t, dir, "app.log", secretLine)
	writeTreeFile(t, dir, "build/output.txt", secretLine)

	opts := DefaultOptions()
	opts.Ignore = []string{"*.log", "build/"}

	findings, err := Dir(dir, opts)
	if err != nil {
		t.Fatalf("Dir: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1: %+v", len(findings), findings)
	}
	if findings[0].Path != filepath.Join(dir, "keep.txt") {
		t.Errorf("Path = %q, want keep.txt", findings[0].Path)
	}
}

func TestDirSkipsBinaryFiles(t *testing.T) {
	dir := t.TempDir()
	writeTreeFile(t, dir, "clean.txt", secretLine)

	binPath := filepath.Join(dir, "app.bin")
	content := append([]byte("AKIAIOSFODNN7EXAMPLE\x00\x01\x02"), make([]byte, 100)...)
	if err := os.WriteFile(binPath, content, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings, err := Dir(dir, DefaultOptions())
	if err != nil {
		t.Fatalf("Dir: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1: %+v", len(findings), findings)
	}
	if findings[0].Path != filepath.Join(dir, "clean.txt") {
		t.Errorf("Path = %q, want clean.txt", findings[0].Path)
	}
}
