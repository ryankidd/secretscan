package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestFileDetectsAWSAccessKeyID(t *testing.T) {
	path := writeFile(t, "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")

	findings, err := File(path, DefaultOptions())
	if err != nil {
		t.Fatalf("File: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if got := findings[0]; got.Detector != "AWS Access Key ID" || got.Token != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("finding = %+v", got)
	}
}

func TestFileDetectsGitHubToken(t *testing.T) {
	const token = "ghp_123456789012345678901234567890123456"
	path := writeFile(t, "GITHUB_TOKEN="+token+"\n")

	findings, err := File(path, DefaultOptions())
	if err != nil {
		t.Fatalf("File: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.Detector == "GitHub Token" && f.Token == token {
			found = true
		}
	}
	if !found {
		t.Fatalf("findings = %+v, want a GitHub Token match for %q", findings, token)
	}
}

func TestFileDetectsPrivateKeyHeader(t *testing.T) {
	path := writeFile(t, "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n")

	findings, err := File(path, DefaultOptions())
	if err != nil {
		t.Fatalf("File: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if got := findings[0]; got.Detector != "Private Key Header" || got.Line != 1 {
		t.Errorf("finding = %+v", got)
	}
}

func TestFileIgnoresTextThatDoesNotMatchAnyDetector(t *testing.T) {
	path := writeFile(t, "just a normal line of text\n")

	findings, err := File(path, DefaultOptions())
	if err != nil {
		t.Fatalf("File: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}
