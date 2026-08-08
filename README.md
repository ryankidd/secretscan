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

Exit status is non-zero when a possible secret is found, so it can be used
as a CI check.

### Ignoring files

Directory scans skip `.git/`, `node_modules/`, and `vendor/` by default.
Add your own gitignore-style glob patterns with a repeatable `-ignore` flag:

```bash
go run . -ignore '*.log' -ignore 'testdata/' path/to/directory
```

A pattern ending in `/` matches directories only. Patterns are matched
against both a file's base name and its path relative to the scan root.

## Status

Early and under active development. Scans a single file or a directory
tree, using pattern-based detectors for AWS keys, GitHub tokens, and
private key headers, plus entropy-based detection for everything else. A
git history scan mode is in progress.

## Development

```bash
go build ./...
go vet ./...
go test ./...
```
