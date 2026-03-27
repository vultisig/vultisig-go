package address

import (
	"testing"

	"github.com/stretchr/testify/assert"
	
	"github.com/vultisig/vultisig-go/common"
)

func TestGetDogecoinAddress(t *testing.T) {
	tests := []struct {
		name  string
		chain common.Chain
		want  string
	}{
		{
			name:  "Dogecoin",
			chain: common.Dogecoin,
			want:  "DRWGYYXGHheFSjRBHQNePRf79erLqUWos6",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			childPublicKey, err := getDerivedPubKey(testECDSAPublicKey, testHexChainCode, tt.chain.GetDerivePath())
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			got, err := GetDogecoinAddress(childPublicKey)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
