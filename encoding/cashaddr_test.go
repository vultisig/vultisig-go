package encoding_test

import (
	"strings"
	"testing"

	"github.com/vultisig/vultisig-go/encoding"
)

// TestCashAddrEncode checks addresses against gcash/bchutil's encoder.
func TestCashAddrEncode(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		addrType byte
		hash     string // hex
		want     string // full address including prefix
	}{
		// P2PKH (addrType = 0x00) test vectors from the spec
		{
			"P2PKH 20-byte zero hash",
			"bitcoincash", encoding.CashAddrP2PKH,
			"0000000000000000000000000000000000000000",
			"bitcoincash:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks603",
		},
		{
			"P2PKH known address 1",
			"bitcoincash", encoding.CashAddrP2PKH,
			"76a04053bda0a6309d9a2b4b8fbd40b6e39f3a0b",
			"bitcoincash:qpm2qsznhks2vvyang45hraagzmw88e6pvgv9hjrhc",
		},
		{
			"P2PKH known address 2",
			"bitcoincash", encoding.CashAddrP2PKH,
			"cb481232299cd5743151ac4b2d63ae198e7bb0a9",
			"bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy",
		},
		{
			"P2PKH known address 3",
			"bitcoincash", encoding.CashAddrP2PKH,
			"011f28e473c95f4013d7d53ec5fbc3b42df8ed10",
			"bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r",
		},
		{
			"P2PKH known address 4",
			"bitcoincash", encoding.CashAddrP2PKH,
			"f2aa822745c9ab44394048c59bb7e1c07b7e53a6",
			"bitcoincash:qre24q38ghy6k3pegpyvtxahu8q8kljn5c46hzjec6",
		},
		// P2SH (addrType = 0x08) test vectors
		{
			"P2SH 20-byte zero hash",
			"bitcoincash", encoding.CashAddrP2SH,
			"0000000000000000000000000000000000000000",
			"bitcoincash:pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq7k2ehe5v",
		},
		{
			"P2SH known address 1",
			"bitcoincash", encoding.CashAddrP2SH,
			"76a04053bda0a6309d9a2b4b8fbd40b6e39f3a0b",
			"bitcoincash:ppm2qsznhks2vvyang45hraagzmw88e6pvlfcc4qv9",
		},
		{
			"P2SH known address 2",
			"bitcoincash", encoding.CashAddrP2SH,
			"cb481232299cd5743151ac4b2d63ae198e7bb0a9",
			"bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e",
		},
		// bchtest prefix
		{
			"P2PKH testnet",
			"bchtest", encoding.CashAddrP2PKH,
			"76a04053bda0a6309d9a2b4b8fbd40b6e39f3a0b",
			"bchtest:qpm2qsznhks2vvyang45hraagzmw88e6pvv7pss5sy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := hexDecode(t, tt.hash)
			got, err := encoding.CashAddrEncode(tt.prefix, tt.addrType, hash)
			if err != nil {
				t.Fatalf("CashAddrEncode: %v", err)
			}
			if strings.ToLower(got) != strings.ToLower(tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCashAddrEncodeInvalidType(t *testing.T) {
	if _, err := encoding.CashAddrEncode("bitcoincash", 0x10, make([]byte, 20)); err == nil {
		t.Error("expected error for address type 0x10, got nil")
	}
}

func TestCashAddrEncodeInvalidHashLength(t *testing.T) {
	_, err := encoding.CashAddrEncode("bitcoincash", encoding.CashAddrP2PKH, make([]byte, 19))
	if err == nil {
		t.Error("expected error for 19-byte hash, got nil")
	}
	_, err = encoding.CashAddrEncode("bitcoincash", encoding.CashAddrP2PKH, make([]byte, 21))
	if err == nil {
		t.Error("expected error for 21-byte hash, got nil")
	}
}

func TestCashAddrValidHashLengths(t *testing.T) {
	// All spec-allowed hash lengths should succeed.
	for _, size := range []int{20, 24, 28, 32, 40, 48, 56, 64} {
		_, err := encoding.CashAddrEncode("bitcoincash", encoding.CashAddrP2PKH, make([]byte, size))
		if err != nil {
			t.Errorf("size %d: unexpected error: %v", size, err)
		}
	}
}
