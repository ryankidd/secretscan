package scan

import "regexp"

// Detector matches a known credential shape via regular expression.
type Detector struct {
	Name    string
	Pattern *regexp.Regexp
}

// Detectors are the built-in regex-based detectors for known credential
// formats, run against every line in addition to entropy-based scanning.
var Detectors = []Detector{
	{
		Name:    "AWS Access Key ID",
		Pattern: regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`),
	},
	{
		Name:    "GitHub Token",
		Pattern: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b`),
	},
	{
		Name:    "Private Key Header",
		Pattern: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`),
	},
}
