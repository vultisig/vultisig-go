package encoding_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/vultisig/vultisig-go/encoding"
)

// TestEIP55Checksum tests the official EIP-55 test vectors.
// https://eips.ethereum.org/EIPS/eip-55
func TestEIP55Checksum(t *testing.T) {
	tests := []struct {
		name string
		want string // expected checksummed address including "0x"
	}{
		// All caps from EIP-55 spec:
		{"1", "0x52908400098527886E0F7030069857D2E4169EE7"},
		{"2", "0x8617E340B3D01FA5F11F306F4090FD50E238070D"},
		// All lower:
		{"3", "0xde709f2102306220921060314715629080e2fb77"},
		{"4", "0x27b1fdb04752bbc536007a920d24acb045561c26"},
		// Mixed case:
		{"5", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{"6", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"},
		{"7", "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"},
		{"8", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addrHex := strings.ToLower(strings.TrimPrefix(tt.want, "0x"))
			addrBytes, err := hex.DecodeString(addrHex)
			if err != nil {
				t.Fatalf("bad test hex: %v", err)
			}
			got := encoding.EIP55Checksum(addrBytes)
			if got != tt.want {
				t.Errorf("EIP55Checksum(%s) = %q, want %q", addrHex, got, tt.want)
			}
		})
	}
}

func TestEIP55ChecksumIdempotent(t *testing.T) {
	addrHex := "52908400098527886e0f7030069857d2e4169ee7"
	b, _ := hex.DecodeString(addrHex)
	first := encoding.EIP55Checksum(b)
	second := encoding.EIP55Checksum(b)
	if first != second {
		t.Errorf("not idempotent: %q vs %q", first, second)
	}
}
