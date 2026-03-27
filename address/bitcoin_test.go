package address

import (
	"testing"

	"github.com/stretchr/testify/assert"
	
	"github.com/vultisig/vultisig-go/common"
)

func TestGetBitcoinAddress(t *testing.T) {
	tests := []struct {
		name  string
		chain common.Chain
		want  string
	}{
		{
			name:  "Bitcoin",
			chain: common.Bitcoin,
			want:  "bc1qf7fmzrldk8jl6y498a4vulvsq3ex22855cljxm",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			childPublicKey, err := getDerivedPubKey(testECDSAPublicKey, testHexChainCode, tt.chain.GetDerivePath())
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			got, err := GetBitcoinAddress(childPublicKey)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
