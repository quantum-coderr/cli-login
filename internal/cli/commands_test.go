package cli

import "testing"

// Pins down exactly what isSixDigitCode accepts and rejects.
func TestIsSixDigitCode(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"valid six digits", "123456", true},
		{"empty string", "", false},
		{"too short", "12345", false},
		{"too long", "1234567", false},
		{"contains a letter", "12345a", false},
		{"contains a space", "12 456", false},
		{"leading zeros are fine", "000123", true},
		{"all zeros is a valid shape", "000000", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := isSixDigitCode(c.in)
			if got != c.want {
				t.Errorf("isSixDigitCode(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
