# secretscan

A CLI that scans files for strings that are likely to be secrets — API
keys, tokens, and other credentials that shouldn't be committed to a
repository.

```bash
go run . path/to/file
```

Every line is checked against two kinds of detector:

- **Pattern-based**: regexes for known credential shapes — AWS access key
  IDs, GitHub tokens, and PEM private key headers.
- **Entropy-based**: tokens above a minimum length whose Shannon entropy
  exceeds a threshold, which catches high-randomness strings like generated
  API keys that don't match a known format.

Exit status is non-zero when a possible secret is found, so it can be used
as a CI check.

## Status

Early and under active development. Currently scans a single file using
pattern-based detectors for AWS keys, GitHub tokens, and private key
headers, plus entropy-based detection for everything else. Recursive
directory scanning and a git history scan mode are in progress.

## Development

```bash
go build ./...
go vet ./...
go test ./...
```
