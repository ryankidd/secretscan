package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileFindsHighEntropyToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	content := "hello world, nothing to see here\n" +
		"AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings, err := File(path, DefaultOptions())
	if err != nil {
		t.Fatalf("File: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}

	got := findings[0]
	if got.Line != 2 {
		t.Errorf("Line = %d, want 2", got.Line)
	}
	if got.Path != path {
		t.Errorf("Path = %q, want %q", got.Path, path)
	}
	if got.Entropy < DefaultEntropyThreshold {
		t.Errorf("Entropy = %.2f, want >= %.2f", got.Entropy, DefaultEntropyThreshold)
	}
}

func TestFileIgnoresShortTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(path, []byte("key=abc123\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings, err := File(path, DefaultOptions())
	if err != nil {
		t.Fatalf("File: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}
