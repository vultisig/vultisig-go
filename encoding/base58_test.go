package encoding_test

import (
	"encoding/hex"
	"testing"

	"github.com/vultisig/vultisig-go/encoding"
)

func TestBase58Encode(t *testing.T) {
	tests := []struct {
		name  string
		input string // hex
		want  string
	}{
		// Single zero byte → leading '1' (first char of standard alphabet)
		{"zero byte", "00", "1"},
		{"two zero bytes", "0000", "11"},
		// 0x39 = 57 decimal → last character of alphabet = 'z'
		{"0x39", "39", "z"},
		// 32 zero bytes (null Solana-style key)
		{"32 zero bytes", "0000000000000000000000000000000000000000000000000000000000000000", "11111111111111111111111111111111"},
		// From Bitcoin wiki: RIPEMD160(SHA256(pubkey)) without version byte
		// pubkey = 0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352
		// hash160 = ecd547d4a9bbad25ce2bccb622ae39d29a625300
		// Raw Base58 of the 20-byte hash (no version, no checksum)
		{"bitcoin wiki hash160", "ecd547d4a9bbad25ce2bccb622ae39d29a625300", "4JNTq8tysm5mu6zXFSonQDMefaAK"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := hex.DecodeString(tt.input)
			if err != nil {
				t.Fatalf("bad test hex: %v", err)
			}
			got := encoding.Base58Encode(b)
			if got != tt.want {
				t.Errorf("Base58Encode(%s) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBase58CheckEncode(t *testing.T) {
	tests := []struct {
		name  string
		input string // hex — the versioned payload WITHOUT checksum (version + hash160)
		want  string
	}{
		// Bitcoin mainnet P2PKH: version 0x00 + hash160 of the wiki public key
		// pubkey = 0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352
		// hash160 = ecd547d4a9bbad25ce2bccb622ae39d29a625300
		{
			"bitcoin P2PKH",
			"00ecd547d4a9bbad25ce2bccb622ae39d29a625300",
			"1NbFyGVTD7VjC2j5bwqj3ZRthkj4sAeDGh",
		},
		// Bitcoin P2SH: version 0x05 + 20 zero bytes
		{
			"P2SH all-zero hash",
			"050000000000000000000000000000000000000000",
			"31h1vYVSYuKP6AhS86fbRdMw9XHieotbST",
		},
		// Dogecoin: version 0x1E + 20 zero bytes → starts with 'D'
		{
			"Dogecoin all-zero hash",
			"1e0000000000000000000000000000000000000000",
			"D596YFweJQuHY1BbjazZYmAbt8jJPbKehC",
		},
		// Zcash transparent P2PKH prefix: 0x1C 0xB8 + 20 zero bytes → starts with 't1'
		{
			"Zcash t1 all-zero hash",
			"1cb80000000000000000000000000000000000000000",
			"t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := hex.DecodeString(tt.input)
			if err != nil {
				t.Fatalf("bad test hex: %v", err)
			}
			got := encoding.Base58CheckEncode(b)
			if got != tt.want {
				t.Errorf("Base58CheckEncode(%s) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBase58EncodeAlphabet_XRP(t *testing.T) {
	// XRP uses the Ripple alphabet instead of the Bitcoin one.
	const xrpAlphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

	tests := []struct {
		name  string
		input string // hex
		want  string
	}{
		// XRP alphabet: position 0 = 'r', so leading zero bytes become 'r'
		{"zero byte xrp", "00", "r"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := hex.DecodeString(tt.input)
			if err != nil {
				t.Fatalf("bad test hex: %v", err)
			}
			got := encoding.Base58EncodeAlphabet(b, xrpAlphabet)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBase58AddressPrefixes(t *testing.T) {
	// Verify that version bytes produce the correct address prefix characters.
	cases := []struct {
		version byte
		prefix  byte
	}{
		{0x00, '1'}, // Bitcoin P2PKH
		{0x05, '3'}, // Bitcoin P2SH
		{0x1E, 'D'}, // Dogecoin
		{0x4C, 'X'}, // Dash
	}
	for _, c := range cases {
		payload := append([]byte{c.version}, make([]byte, 20)...)
		addr := encoding.Base58CheckEncode(payload)
		if len(addr) == 0 || addr[0] != c.prefix {
			t.Errorf("version 0x%02x: expected address starting with %q, got %q", c.version, c.prefix, addr)
		}
	}
}
