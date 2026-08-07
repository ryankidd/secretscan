package scan

import "math"

// ShannonEntropy returns the Shannon entropy of s, in bits per character.
// Higher values indicate more randomness; typical English words and
// identifiers score low, while high-entropy strings like API keys and
// generated tokens score high.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}

	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}

	length := float64(len([]rune(s)))
	var entropy float64
	for _, count := range counts {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}
