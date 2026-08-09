package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// initRepo creates a git repository in a temp dir and returns its path. It
// fails the test if git isn't configured well enough to make a commit.
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	run("init", "-q", "-b", "main")
	run("config", "commit.gpgsign", "false")
	return dir
}

// commitFile writes content to path within dir and commits it.
func commitFile(t *testing.T, dir, path, content, message string) {
	t.Helper()
	full := filepath.Join(dir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	for _, args := range [][]string{{"add", path}, {"commit", "-q", "-m", message}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func TestGitHistoryFindsSecretInPastCommit(t *testing.T) {
	dir := initRepo(t)
	commitFile(t, dir, "README.md", "just a readme\n", "add readme")
	commitFile(t, dir, "config.yml", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n", "add config")
	commitFile(t, dir, "config.yml", "aws_access_key_id = REDACTED\n", "redact secret")

	findings, err := GitHistory(dir, DefaultOptions())
	if err != nil {
		t.Fatalf("GitHistory: %v", err)
	}

	var found *Finding
	for i, f := range findings {
		if f.Detector == "AWS Access Key ID" {
			found = &findings[i]
		}
	}
	if found == nil {
		t.Fatalf("findings = %+v, want an AWS Access Key ID match", findings)
	}
	if found.Path != "config.yml" {
		t.Errorf("Path = %q, want config.yml", found.Path)
	}
	if found.Line != 1 {
		t.Errorf("Line = %d, want 1", found.Line)
	}
	if found.Commit == "" {
		t.Error("Commit is empty, want the commit that introduced the secret")
	}
}

func TestGitHistoryIgnoresCleanRepo(t *testing.T) {
	dir := initRepo(t)
	commitFile(t, dir, "README.md", "just a readme\n", "add readme")
	commitFile(t, dir, "notes.txt", "nothing interesting here\n", "add notes")

	findings, err := GitHistory(dir, DefaultOptions())
	if err != nil {
		t.Fatalf("GitHistory: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0: %+v", len(findings), findings)
	}
}
