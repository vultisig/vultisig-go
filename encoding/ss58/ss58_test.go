package ss58_test

import (
	"encoding/hex"
	"testing"

	"github.com/vultisig/vultisig-go/encoding/ss58"
)

// TestSS58Encode tests vectors from the Substrate documentation and Polkadot.js.
// Reference: https://docs.substrate.io/reference/address-formats/
func TestSS58Encode(t *testing.T) {
	// "Alice" — the canonical Substrate test key used in all substrate test suites.
	const alicePubKey = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"

	tests := []struct {
		name   string
		pubkey string
		format uint16
		want   string
	}{
		// Format 0: Polkadot
		{
			"Alice Polkadot",
			alicePubKey,
			0,
			"15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5",
		},
		// Format 2: Kusama
		{
			"Alice Kusama",
			alicePubKey,
			2,
			"HNZata7iMYWmk5RvZRTiAsSDhV8366zq2YGb3tLH5Upf74F",
		},
		// Format 42: generic Substrate / Bittensor
		{
			"Alice generic (Bittensor)",
			alicePubKey,
			42,
			"5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
		},
		// A second well-known Substrate key — "Bob"
		{
			"Bob generic",
			"8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48",
			42,
			"5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
		},
		// Format 10: Acala
		{
			"Alice Acala",
			alicePubKey,
			10,
			"25fqepuLngYL2DK9ApTejNzqPadUUZ9ALYyKWX2jyvEiuZLa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := hex.DecodeString(tt.pubkey)
			if err != nil {
				t.Fatalf("bad pubkey hex: %v", err)
			}
			got, err := ss58.SS58Encode(pub, tt.format)
			if err != nil {
				t.Fatalf("SS58Encode: %v", err)
			}
			if got != tt.want {
				t.Errorf("SS58Encode(format=%d) = %q, want %q", tt.format, got, tt.want)
			}
		})
	}
}

func TestSS58EncodeFormatPrefix(t *testing.T) {
	// Polkadot addresses (format 0) start with '1'.
	// Kusama addresses (format 2) start with 'C' or 'D' (key-dependent).
	// Generic/Bittensor addresses (format 42) start with '5'.
	alicePub, _ := hex.DecodeString("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")

	addr0, _ := ss58.SS58Encode(alicePub, 0)
	if len(addr0) == 0 || addr0[0] != '1' {
		t.Errorf("Polkadot address should start with '1', got %q", addr0)
	}

	addr42, _ := ss58.SS58Encode(alicePub, 42)
	if len(addr42) == 0 || addr42[0] != '5' {
		t.Errorf("Generic address should start with '5', got %q", addr42)
	}
}
