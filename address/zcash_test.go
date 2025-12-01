package address

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vultisig/mobile-tss-lib/tss"

	"github.com/vultisig/vultisig-go/common"
)

func TestGetZcashAddress(t *testing.T) {
	tests := []struct {
		name  string
		chain common.Chain
		want  string
	}{
		{
			name:  "Zcash",
			chain: common.Zcash,
			want:  "t1UJkDvXWkyZjkkRScLxzFJCxcBgq63NZED",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			childPublicKey, err := tss.GetDerivedPubKey(testECDSAPublicKey, testHexChainCode, tt.chain.GetDerivePath(), false)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			got, err := GetZcashAddress(childPublicKey)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestZcashAddressFormat(t *testing.T) {
	// Test that the generated address starts with "t1" (mainnet P2PKH)
	childPublicKey, err := tss.GetDerivedPubKey(testECDSAPublicKey, testHexChainCode, common.Zcash.GetDerivePath(), false)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	addr, err := GetZcashAddress(childPublicKey)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	// Zcash mainnet P2PKH addresses start with "t1"
	assert.True(t, len(addr) > 2, "address should be longer than 2 characters")
	assert.Equal(t, "t1", addr[:2], "Zcash mainnet address should start with 't1'")
}

