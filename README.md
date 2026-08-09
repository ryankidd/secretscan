# secretscan

A CLI that scans files for strings that are likely to be secrets — API
keys, tokens, and other credentials that shouldn't be committed to a
repository.

```bash
go run . path/to/file
go run . path/to/directory
```

Pointing secretscan at a directory walks it recursively and scans every
regular file it finds. Files that look like binary data (a NUL byte in the
first few KB) are skipped, since entropy scanning them is both slow and
noisy.

Every line of a scanned file is checked against two kinds of detector:

- **Pattern-based**: regexes for known credential shapes — AWS access key
  IDs, GitHub tokens, and PEM private key headers.
- **Entropy-based**: tokens above a minimum length whose Shannon entropy
  exceeds a threshold, which catches high-randomness strings like generated
  API keys that don't match a known format.

Exit status distinguishes a clean scan from a broken one, so a CI step can
tell "found secrets" apart from "the scan itself failed":

| Exit status | Meaning |
|---|---|
| `0` | No findings |
| `1` | One or more possible secrets found |
| `2` | The scan couldn't run (bad arguments, unreadable path, git failure) |

### Ignoring files

Directory scans skip `.git/`, `node_modules/`, and `vendor/` by default.
Add your own gitignore-style glob patterns with a repeatable `-ignore` flag:

```bash
go run . -ignore '*.log' -ignore 'testdata/' path/to/directory
```

A pattern ending in `/` matches directories only. Patterns are matched
against both a file's base name and its path relative to the scan root.

### Scanning git history

`-history` scans commit history instead of the working tree. Each commit's
diff is checked, so secrets caught this way are reported even if a later
commit removed them:

```bash
go run . -history path/to/repo
```

Findings from history include the commit that introduced the line:

```
config.yml@a1b2c3d:1: possible secret (AWS Access Key ID): AKIA...
```

### JSON output

`-format json` prints findings as a JSON array instead of the default
human-readable lines, for feeding into other tooling:

```bash
go run . -format json path/to/directory
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

## Status

Early and under active development. Scans a single file, a directory tree,
or a repository's commit history, using pattern-based detectors for AWS
keys, GitHub tokens, and private key headers, plus entropy-based detection
for everything else. Output is available as plain text or JSON.

## Development

```bash
go build ./...
go vet ./...
go test ./...
```
