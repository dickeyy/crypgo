package crypto

import (
	"encoding/hex"
	"testing"
)

func TestSHA256(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			"abc",
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
		{
			"",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			"hello world",
			"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
	}

	for _, test := range tests {
		result := SHA256([]byte(test.input))
		if hex.EncodeToString(result) != test.expected {
			t.Errorf("SHA256(%s) = %s; want %s",
				test.input,
				hex.EncodeToString(result),
				test.expected)
		}
	}
}
