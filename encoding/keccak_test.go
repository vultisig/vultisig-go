package encoding_test

import (
	"encoding/hex"
	"testing"

	"github.com/vultisig/vultisig-go/encoding"
)

// TestKeccak256 tests canonical Keccak-256 vectors.
// These are NOT SHA3-256 vectors — Keccak-256 uses 0x01 domain separation while
// NIST SHA3-256 uses 0x06. The values below will fail against crypto/sha3.
func TestKeccak256(t *testing.T) {
	tests := []struct {
		name  string
		input string // literal string input
		want  string // expected hex output
	}{
		{
			"empty string",
			"",
			"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
		{
			"abc",
			"abc",
			"4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
		},
		{
			"testing",
			"testing",
			"5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02",
		},
		{
			"hello world",
			"hello world",
			"47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad",
		},
		{
			"The quick brown fox jumps over the lazy dog",
			"The quick brown fox jumps over the lazy dog",
			"4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encoding.Keccak256([]byte(tt.input))
			if hex.EncodeToString(got[:]) != tt.want {
				t.Errorf("Keccak256(%q) = %x, want %s", tt.input, got, tt.want)
			}
		})
	}
}

func TestKeccak256SingleByte(t *testing.T) {
	// These are the correct Keccak-256 (not SHA3-256) values for single bytes.
	tests := []struct {
		input byte
		want  string
	}{
		{0x00, "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a"},
		{0x01, "5fe7f977e71dba2ea1a68e21057beebb9be2ac30c6410aa38d4f3fbe41dcffd2"},
	}
	for _, tt := range tests {
		got := encoding.Keccak256([]byte{tt.input})
		if hex.EncodeToString(got[:]) != tt.want {
			t.Errorf("Keccak256([0x%02x]) = %x, want %s", tt.input, got, tt.want)
		}
	}
}

// TestKeccak256NotSHA3 confirms that our output differs from NIST SHA3-256.
// SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
// Keccak-256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
func TestKeccak256NotSHA3(t *testing.T) {
	sha3EmptyHex := "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
	got := encoding.Keccak256([]byte{})
	if hex.EncodeToString(got[:]) == sha3EmptyHex {
		t.Error("Keccak256 must NOT equal SHA3-256 — wrong padding used")
	}
}

// TestKeccak256MultiBlock ensures correct handling of inputs spanning multiple
// rate blocks (rate = 136 bytes for Keccak-256).
func TestKeccak256MultiBlock(t *testing.T) {
	input := make([]byte, 200)
	for i := range input {
		input[i] = byte(i)
	}
	// Computed with our implementation and cross-checked as Keccak-256 (not SHA3).
	want := "bfb0aa97863e797943cf7c33bb7e880bb4543f3d2703c0923c6901c2af57b890"
	got := encoding.Keccak256(input)
	if hex.EncodeToString(got[:]) != want {
		t.Errorf("multi-block: got %x, want %s", got, want)
	}
}
