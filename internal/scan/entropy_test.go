package scan

import "testing"

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want float64
	}{
		{"empty", "", 0},
		{"single repeated character", "aaaaaaaa", 0},
		{"high entropy token", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", 4.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShannonEntropy(tt.s)
			if tt.name == "high entropy token" {
				if got < tt.want {
					t.Fatalf("ShannonEntropy(%q) = %.2f, want >= %.2f", tt.s, got, tt.want)
				}
				return
			}
			if got != tt.want {
				t.Fatalf("ShannonEntropy(%q) = %.2f, want %.2f", tt.s, got, tt.want)
			}
		})
	}
}
