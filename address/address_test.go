package address

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vultisig/vultisig-go/common"
)

func TestGetAddress(t *testing.T) {
	successTests := []struct {
		name     string
		chain    common.Chain
		want     string
		inputKey string
		isEdDSA  bool
	}{
		{
			name:     "BitcoinCash",
			chain:    common.BitcoinCash,
			want:     "qql2xsfqh7ktgrp0emcpzzw0zscc5j7uacl0vutypy",
			inputKey: testECDSAPublicKey,
			isEdDSA:  false,
		},
		{
			name:     "Bitcoin",
			chain:    common.Bitcoin,
			want:     "bc1qf7fmzrldk8jl6y498a4vulvsq3ex22855cljxm",
			inputKey: testECDSAPublicKey,
			isEdDSA:  false,
		},
		{
			name:     "Sui",
			chain:    common.Sui,
			want:     "0x2a5eb4cbdc14bfffb5cad5afe22a335e5860c20f2cf48be1d06062b53b27e2ce",
			inputKey: testEdDSAPublicKey,
			isEdDSA:  true,
		},
		{
			name:     "Zcash",
			chain:    common.Zcash,
			want:     "t1HvTBYqG3yLnHzaMxXuw3hp4Bx5yHFtWwu",
			inputKey: testECDSAPublicKey,
			isEdDSA:  false,
		},
	}

	failureTests := []struct {
		name     string
		chain    common.Chain
		wantErr  error
		inputKey string
		isEdDSA  bool
	}{
		{
			name:     "Invalid root hex public key",
			chain:    common.Sui,
			wantErr:  fmt.Errorf("invalid public key: "),
			inputKey: "",
			isEdDSA:  false,
		},
	}

	for _, tt := range successTests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotPublicKey, gotIsEdDSA, err := GetAddress(tt.inputKey, testHexChainCode, tt.chain)
			if err != nil {
				t.Error(err)
				t.FailNow()
			}
			assert.Equal(t, tt.want, got)
			// We don't support deriving the public key for EdDSA chains
			if !tt.isEdDSA {
				expectedPublicKey, err := getDerivedPubKey(tt.inputKey, testHexChainCode, tt.chain.GetDerivePath())
				if err != nil {
					t.Error(err)
					t.FailNow()
				}
				assert.Equal(t, expectedPublicKey, gotPublicKey)
			} else {
				assert.Equal(t, tt.inputKey, gotPublicKey)
			}

			assert.Equal(t, tt.isEdDSA, gotIsEdDSA)
		})
	}

	for _, tt := range failureTests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := GetAddress(tt.inputKey, testHexChainCode, tt.chain)
			if err == nil {
				t.Errorf("expected error: %v", tt.wantErr)
				t.FailNow()
			}
			assert.Equal(t, tt.wantErr, err)
		})
	}
}
