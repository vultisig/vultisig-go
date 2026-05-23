package address

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vultisig/mobile-tss-lib/tss"
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
				expectedPublicKey, err := tss.GetDerivedPubKey(tt.inputKey, testHexChainCode, tt.chain.GetDerivePath(), tt.chain.IsEdDSA())
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

// Regression pin for the 2026-05-22 bug shape: callers (notably
// agent-backend's `addressbook.DeriveAndStore`) were passing the
// 33-byte compressed ECDSA pubkey for EdDSA chains. Pre-fix, the
// chain-specific helpers (`GetSolAddress`, `GetSuiAddress`, etc.)
// happily base58/blake2b'd the ECDSA bytes and produced
// confidently-wrong addresses (44 chars for Solana, 64 hex chars
// for Sui, etc.) that decoded to the ECDSA pubkey itself — every
// Solana / Sui / Polkadot / Ton / Cardano / Bittensor row in
// `user_addresses` was garbage. Now `GetAddress` rejects the
// 33-byte-for-EdDSA shape at the dispatch boundary so a missing
// EdDSA pubkey surface in the caller fails loud.
func TestGetAddress_RejectsECDSAPubkeyOnEdDSAChain(t *testing.T) {
	edDSAChains := []common.Chain{
		common.Solana,
		common.Sui,
		common.Polkadot,
		common.Bittensor,
		common.Ton,
		common.Cardano,
	}
	for _, chain := range edDSAChains {
		t.Run(chain.String(), func(t *testing.T) {
			// Passing the 66-hex (33-byte) ECDSA root pubkey to an
			// EdDSA chain MUST fail — that's the bug shape.
			_, _, _, err := GetAddress(testECDSAPublicKey, testHexChainCode, chain)
			if err == nil {
				t.Fatalf("expected error rejecting 33-byte ECDSA pubkey for EdDSA chain %q, got nil", chain)
			}
			assert.Contains(t, err.Error(), "Ed25519")
		})
	}
}

func TestGetAddress_RejectsEdDSAPubkeyOnECDSAChain(t *testing.T) {
	ecdsaChains := []common.Chain{
		common.Bitcoin,
		common.Ethereum,
		common.GaiaChain,
		common.Tron,
	}
	for _, chain := range ecdsaChains {
		t.Run(chain.String(), func(t *testing.T) {
			// Passing the 64-hex (32-byte) EdDSA root pubkey to an
			// ECDSA chain MUST fail — symmetric to the EdDSA-on-
			// ECDSA-chain case above.
			_, _, _, err := GetAddress(testEdDSAPublicKey, testHexChainCode, chain)
			if err == nil {
				t.Fatalf("expected error rejecting 32-byte EdDSA pubkey for ECDSA chain %q, got nil", chain)
			}
			assert.Contains(t, err.Error(), "secp256k1")
		})
	}
}
