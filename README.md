# secretscan

A CLI that scans files for strings that are likely to be secrets — API keys,
tokens, and other credentials that shouldn't be committed to a repository.

It scans a single file, a directory tree, or a repository's commit history,
using pattern-based detectors for known credential formats plus
entropy-based detection to catch high-randomness tokens that don't match a
known format. Output is plain text or JSON, and exit codes are designed to
be CI-friendly.

## Install

```bash
go install github.com/ryankidd/secretscan@latest
```

Or build from source:

```bash
git clone https://github.com/ryankidd/secretscan.git
cd secretscan
go build .
```

## Usage

```
secretscan [-ignore pattern] [-history] [-format text|json] <file|directory>
```

### Scan a single file

```bash
secretscan config.yml
```

```
config.yml:1: possible secret (AWS Access Key ID): AKIAIOSFODNN7EXAMPLE
```

### Scan a directory

Pointing secretscan at a directory walks it recursively and scans every
regular file it finds. Files that look like binary data (a NUL byte in the
first few KB) are skipped, since entropy scanning them is both slow and
noisy.

```bash
secretscan path/to/repo
```

`.git/`, `node_modules/`, and `vendor/` are skipped by default. Add your own
gitignore-style glob patterns with a repeatable `-ignore` flag:

```bash
secretscan -ignore '*.log' -ignore 'testdata/' path/to/repo
```

A pattern ending in `/` matches directories only. Patterns are matched
against both a file's base name and its path relative to the scan root.

### Scan git history

`-history` scans commit history instead of the working tree. Each commit's
diff is checked, so secrets caught this way are reported even if a later
commit removed them:

```bash
secretscan -history path/to/repo
```

Findings from history include the commit that introduced the line:

```
config.yml@a1b2c3d:2: possible secret (AWS Access Key ID): AKIAIOSFODNN7EXAMPLE
```

### JSON output

`-format json` prints findings as a JSON array instead of the default
human-readable lines, for feeding into other tooling:

```bash
secretscan -format json path/to/repo
```

```json
[
  {
    "path": "config.yml",
    "line": 1,
    "token": "AKIAIOSFODNN7EXAMPLE",
    "detector": "AWS Access Key ID"
  }
]
```

## Detectors

Every line of a scanned file is checked against two kinds of detector:

- **Pattern-based**: regexes for known credential shapes — AWS access key
  IDs, GitHub tokens, and PEM private key headers.
- **Entropy-based**: tokens above a minimum length whose Shannon entropy
  exceeds a threshold, which catches high-randomness strings like generated
  API keys that don't match a known format.

## Exit codes

Exit status distinguishes a clean scan from a broken one, so a CI step can
tell "found secrets" apart from "the scan itself failed":

| Exit status | Meaning |
|---|---|
| `0` | No findings |
| `1` | One or more possible secrets found |
| `2` | The scan couldn't run (bad arguments, unreadable path, git failure) |

## Development

```bash
go build ./...
go vet ./...
go test ./... -race
```
