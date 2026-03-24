package address

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vultisig/vultisig-go/common"
)

var testECDSAPublicKey = "023118028f9e87a0a6a10e84e26d2d8147ea8cb0d00aaf0d91b2ca512fba033120"
var testEdDSAPublicKey = "8265ca17b04e49dd99535d869d3510f30b7f60d60fb884427d59b47d32e6be5e"
var testHexChainCode = "1ea1414310c8f2eb2925b53fe6f7fab0c456a9bbec3e329688b89658dab4d702"

func TestGetSuiAddress(t *testing.T) {
	tests := []struct {
		name  string
		chain common.Chain
		want  string
	}{
		{
			name:  "Sui",
			chain: common.Sui,
			want:  "0x2a5eb4cbdc14bfffb5cad5afe22a335e5860c20f2cf48be1d06062b53b27e2ce",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetSuiAddress(testEdDSAPublicKey)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			t.Logf("Got: %s", got)
			assert.Equal(t, tt.want, got)
		})
	}
}
