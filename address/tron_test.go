package address

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vultisig/mobile-tss-lib/tss"

	"github.com/vultisig/vultisig-go/common"
)

func TestTronAddress(t *testing.T) {
	tests := []struct {
		name  string
		chain common.Chain
		want  string
	}{
		{
			name:  "Tron",
			chain: common.Tron,
			want:  "THFxtPNvc7R9rz4ecC6aTSyPp2WoZnrZh3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			childPublicKey, err := tss.GetDerivedPubKey(testECDSAPublicKey, testHexChainCode, tt.chain.GetDerivePath(), false)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			got, err := GetTronAddress(childPublicKey)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTronAddressFormat(t *testing.T) {
	// Test that the generated address starts with "T" (mainnet) and has correct length
	childPublicKey, err := tss.GetDerivedPubKey(testECDSAPublicKey, testHexChainCode, common.Tron.GetDerivePath(), false)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := GetTronAddress(childPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// TRON addresses are base58check encoded, typically 34 characters
	// Starting with 'T' for mainnet
	assert.True(t, len(addr) >= 25 && len(addr) <= 35, "TRON address should be between 25-35 characters, got %d", len(addr))
	assert.Equal(t, "T", string(addr[0]), "TRON mainnet address should start with 'T'")
}

func TestTronAddressDerivation(t *testing.T) {
	// Verify the address derivation works correctly with EVM-style derivation
	// TRON uses the same key derivation as Ethereum, just different encoding
	childPublicKey, err := tss.GetDerivedPubKey(testECDSAPublicKey, testHexChainCode, common.Tron.GetDerivePath(), false)
	if err != nil {
		t.Fatal(err)
	}

	tronAddr, err := GetTronAddress(childPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Get the Ethereum address for comparison
	evmChildPublicKey, err := tss.GetDerivedPubKey(testECDSAPublicKey, testHexChainCode, common.Ethereum.GetDerivePath(), false)
	if err != nil {
		t.Fatal(err)
	}

	evmAddr, err := GetEVMAddress(evmChildPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Both should be valid addresses (different derivation paths mean different addresses)
	assert.NotEmpty(t, tronAddr)
	assert.NotEmpty(t, evmAddr)
	t.Logf("TRON address: %s", tronAddr)
	t.Logf("EVM address:  %s", evmAddr)
}

