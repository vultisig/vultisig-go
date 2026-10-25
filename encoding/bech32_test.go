package encoding_test

import (
	"strings"
	"testing"

	"github.com/vultisig/vultisig-go/encoding"
)

// TestBech32ValidAddresses tests vectors from BIP-173.
// Witness programs are obtained by decoding the bech32 address.
// https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
func TestBech32ValidAddresses(t *testing.T) {
	tests := []struct {
		name    string
		hrp     string
		version byte
		program string // hex — the raw witness program bytes
		addr    string // expected bech32 address (lowercase)
	}{
		{
			"P2WPKH mainnet",
			"bc", 0,
			// program decoded from bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
			"751e76e8199196d454941c45d1b3a323f1433bd6",
			"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		},
		{
			"P2WSH mainnet",
			"bc", 0,
			// program decoded from bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3
			"1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
			"bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
		},
		{
			"P2WPKH testnet",
			"tb", 0,
			"751e76e8199196d454941c45d1b3a323f1433bd6",
			"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
		},
		{
			"P2WPKH litecoin",
			"ltc", 0,
			"751e76e8199196d454941c45d1b3a323f1433bd6",
			"ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prog := hexDecode(t, tt.program)
			fiveBit, err := encoding.ConvertBits(prog, 8, 5, true)
			if err != nil {
				t.Fatalf("ConvertBits: %v", err)
			}
			data := append([]int{int(tt.version)}, fiveBit...)
			got := encoding.Bech32Encode(tt.hrp, data)
			if strings.ToLower(got) != strings.ToLower(tt.addr) {
				t.Errorf("got %q, want %q", got, tt.addr)
			}
		})
	}
}

// TestBech32EncodeBytes tests the Bech32EncodeBytes convenience function using
// addresses verified against the vultisig address test suite.
func TestBech32EncodeBytes(t *testing.T) {
	// hash160 of the vultisig test ECDSA public key
	// (023118028f9e87a0a6a10e84e26d2d8147ea8cb0d00aaf0d91b2ca512fba033120 — pre-derivation)
	// Actual hash160 used in address tests comes from the derived key per chain.
	// We use independently computed hash → address pairs verified against GetBech32Address.
	tests := []struct {
		hrp  string
		hash string // hex — 20-byte hash160
		want string
	}{
		// These are the hash160 of the derived pubkey for the vultisig test key,
		// verified against the passing GetBech32Address test suite.
		{"cosmos", "352fce7c0100a33b9fcaf392f8d1fdedae22abb4", "cosmos1x5huulqpqz3nh8727wf0350aakhz92a5yy74wj"},
		{"thor", "352fce7c0100a33b9fcaf392f8d1fdedae22abb4", "thor1x5huulqpqz3nh8727wf0350aakhz92a5zr8wmd"},
		{"osmo", "352fce7c0100a33b9fcaf392f8d1fdedae22abb4", "osmo1x5huulqpqz3nh8727wf0350aakhz92a5vld9cq"},
	}
	for _, tt := range tests {
		t.Run(tt.hrp, func(t *testing.T) {
			b := hexDecode(t, tt.hash)
			got, err := encoding.Bech32EncodeBytes(tt.hrp, b)
			if err != nil {
				t.Fatalf("Bech32EncodeBytes: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestConvertBitsRoundTrip verifies 8→5→8 is identity.
func TestConvertBitsRoundTrip(t *testing.T) {
	cases := []string{
		"",
		"00",
		"ff",
		"deadbeef",
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	}
	for _, c := range cases {
		input := hexDecode(t, c)
		five, err := encoding.ConvertBits(input, 8, 5, true)
		if err != nil {
			t.Fatalf("ConvertBits 8→5 for %q: %v", c, err)
		}
		fiveBytes := make([]byte, len(five))
		for i, v := range five {
			fiveBytes[i] = byte(v)
		}
		eight, err := encoding.ConvertBits(fiveBytes, 5, 8, false)
		if err != nil {
			t.Fatalf("ConvertBits 5→8 for %q: %v", c, err)
		}
		eightBytes := make([]byte, len(eight))
		for i, v := range eight {
			eightBytes[i] = byte(v)
		}
		if string(eightBytes) != string(input) {
			t.Errorf("round-trip mismatch for %q: got %x", c, eightBytes)
		}
	}
}

// TestConvertBitsNonZeroPadding verifies that non-zero padding is rejected.
func TestConvertBitsNonZeroPadding(t *testing.T) {
	// [31, 7] in 5-bit groups → converting to 8 bits produces 1 full byte (249)
	// with 2 remaining bits = "11" (non-zero). With pad=false this should error.
	_, err := encoding.ConvertBits([]byte{31, 7}, 5, 8, false)
	if err == nil {
		t.Error("expected error for non-zero padding bits, got nil")
	}
}

// TestConvertBitsIllegalZeroPadding verifies that excess zero-padded groups are rejected.
func TestConvertBitsIllegalZeroPadding(t *testing.T) {
	// A single 5-bit group [0x01] has 5 bits; converting to 8-bit with pad=false
	// results in bits >= fromBits (5 >= 5) → "illegal zero padding" error.
	_, err := encoding.ConvertBits([]byte{0x01}, 5, 8, false)
	if err == nil {
		t.Error("expected error for illegal zero padding, got nil")
	}
}
