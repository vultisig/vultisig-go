package address

import (
	"testing"

	"github.com/stretchr/testify/assert"
	
	"github.com/vultisig/vultisig-go/common"
)

func TestGetBitcoinCashAddress(t *testing.T) {
	tests := []struct {
		name  string
		chain common.Chain
		want  string
	}{
		{
			name:  "BitcoinCash",
			chain: common.BitcoinCash,
			want:  "qql2xsfqh7ktgrp0emcpzzw0zscc5j7uacl0vutypy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			childPublicKey, err := getDerivedPubKey(testECDSAPublicKey, testHexChainCode, tt.chain.GetDerivePath())
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			got, err := GetBitcoinCashAddress(childPublicKey)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
