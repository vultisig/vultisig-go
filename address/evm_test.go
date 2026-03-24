package address

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vultisig/mobile-tss-lib/tss"

	"github.com/vultisig/vultisig-go/common"
)

func TestEVMAddress(t *testing.T) {
	tests := []struct {
		name  string
		chain common.Chain
		want  string
	}{
		{
			name:  "Ethereum",
			chain: common.Ethereum,
			want:  "0x4e2FeBBb157dc6373b1e5fb908F0263c6041302C",
		},
		{
			name:  "Hyperliquid",
			chain: common.Hyperliquid,
			want:  "0x4e2FeBBb157dc6373b1e5fb908F0263c6041302C",
		},
		{
			name:  "Sei",
			chain: common.Sei,
			want:  "0x4e2FeBBb157dc6373b1e5fb908F0263c6041302C",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			childPublicKey, err := tss.GetDerivedPubKey(testECDSAPublicKey, testHexChainCode, tt.chain.GetDerivePath(), false)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			got, err := GetEVMAddress(childPublicKey)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
