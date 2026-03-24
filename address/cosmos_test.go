package address

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vultisig/mobile-tss-lib/tss"

	"github.com/vultisig/vultisig-go/common"
)

func TestGetBech32Address(t *testing.T) {
	tests := []struct {
		name  string
		chain common.Chain
		hrp   string
		want  string
	}{
		{
			name:  "THORChain",
			chain: common.THORChain,
			hrp:   "thor",
			want:  "thor1486j00qg5353cc7xtfkfx75sc9s63y688vhk36",
		},
		{
			name:  "MayaChain",
			chain: common.MayaChain,
			hrp:   "maya",
			want:  "maya1486j00qg5353cc7xtfkfx75sc9s63y688mf682",
		},
		{
			name:  "Cosmos",
			chain: common.GaiaChain,
			hrp:   "cosmos",
			want:  "cosmos1p46u8ctucfrcwwx49004e0lg8unzr87augeda0",
		},
		{
			name:  "Kujira",
			chain: common.Kujira,
			hrp:   "kujira",
			want:  "kujira1p46u8ctucfrcwwx49004e0lg8unzr87adqm4s9",
		},
		{
			name:  "Terra",
			chain: common.Terra,
			hrp:   "terra",
			want:  "terra1zfv82l9n09kxa0jz765vtzh8r7yxtfqr65hr6l",
		},
		{
			name:  "TerraClassic",
			chain: common.TerraClassic,
			hrp:   "terra",
			want:  "terra1zfv82l9n09kxa0jz765vtzh8r7yxtfqr65hr6l",
		},
		{
			name:  "Osmosis",
			chain: common.Osmosis,
			hrp:   "osmo",
			want:  "osmo1p46u8ctucfrcwwx49004e0lg8unzr87a5n2ata",
		},
		{
			name:  "Noble",
			chain: common.Noble,
			hrp:   "noble",
			want:  "noble1p46u8ctucfrcwwx49004e0lg8unzr87a5tv99p",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			childPublicKey, err := tss.GetDerivedPubKey(testECDSAPublicKey, testHexChainCode, tt.chain.GetDerivePath(), false)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			got, err := GetBech32Address(childPublicKey, tt.hrp)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
