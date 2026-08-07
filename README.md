# secretscan

A CLI that scans files for strings that are likely to be secrets — API
keys, tokens, and other credentials that shouldn't be committed to a
repository.

```bash
go run . path/to/file
```

It flags tokens above a minimum length whose Shannon entropy exceeds a
threshold, which catches high-randomness strings like generated API keys
and tokens while ignoring ordinary text. Exit status is non-zero when a
possible secret is found, so it can be used as a CI check.

## Status

Early and under active development. Currently scans a single file using
entropy-based detection. Pattern-based detectors for known credential
formats, recursive directory scanning, and a git history scan mode are in
progress.

## Development

```bash
go build ./...
go vet ./...
go test ./...
```
