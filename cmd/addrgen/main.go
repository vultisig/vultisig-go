package main

import (
	"fmt"
	"os"

	"github.com/vultisig/vultisig-go/address"
	"github.com/vultisig/vultisig-go/common"
)

const (
	testECDSAPublicKey = "023118028f9e87a0a6a10e84e26d2d8147ea8cb0d00aaf0d91b2ca512fba033120"
	testEdDSAPublicKey = "8265ca17b04e49dd99535d869d3510f30b7f60d60fb884427d59b47d32e6be5e"
	testHexChainCode   = "1ea1414310c8f2eb2925b53fe6f7fab0c456a9bbec3e329688b89658dab4d702"
)

type testCase struct {
	chain    common.Chain
	rootKey  string
	expected string
}

func main() {
	cases := []testCase{
		{common.Bitcoin, testECDSAPublicKey, "bc1qf7fmzrldk8jl6y498a4vulvsq3ex22855cljxm"},
		{common.BitcoinCash, testECDSAPublicKey, "qql2xsfqh7ktgrp0emcpzzw0zscc5j7uacl0vutypy"},
		{common.Litecoin, testECDSAPublicKey, "ltc1quvj2dxa8qukcvl3m9r6aep8zp794pudy6sk0gw"},
		{common.Dogecoin, testECDSAPublicKey, "DRWGYYXGHheFSjRBHQNePRf79erLqUWos6"},
		{common.Dash, testECDSAPublicKey, "Xi4XjARgSbmaSVF1h9E6fVhNH95eoQpGNb"},
		{common.Zcash, testECDSAPublicKey, "t1HvTBYqG3yLnHzaMxXuw3hp4Bx5yHFtWwu"},
		{common.THORChain, testECDSAPublicKey, "thor1486j00qg5353cc7xtfkfx75sc9s63y688vhk36"},
		{common.MayaChain, testECDSAPublicKey, "maya1486j00qg5353cc7xtfkfx75sc9s63y688mf682"},
		{common.GaiaChain, testECDSAPublicKey, "cosmos1p46u8ctucfrcwwx49004e0lg8unzr87augeda0"},
		{common.Kujira, testECDSAPublicKey, "kujira1p46u8ctucfrcwwx49004e0lg8unzr87adqm4s9"},
		{common.Dydx, testECDSAPublicKey, "dydx1p46u8ctucfrcwwx49004e0lg8unzr87a43hfac"},
		{common.TerraClassic, testECDSAPublicKey, "terra1zfv82l9n09kxa0jz765vtzh8r7yxtfqr65hr6l"},
		{common.Terra, testECDSAPublicKey, "terra1zfv82l9n09kxa0jz765vtzh8r7yxtfqr65hr6l"},
		{common.Osmosis, testECDSAPublicKey, "osmo1p46u8ctucfrcwwx49004e0lg8unzr87a5n2ata"},
		{common.Noble, testECDSAPublicKey, "noble1p46u8ctucfrcwwx49004e0lg8unzr87a5tv99p"},
		{common.Akash, testECDSAPublicKey, "akash1p46u8ctucfrcwwx49004e0lg8unzr87a3n52y4"},
		{common.Ethereum, testECDSAPublicKey, "0x4e2FeBBb157dc6373b1e5fb908F0263c6041302C"},
		{common.Tron, testECDSAPublicKey, "TJrWD5rnnK5vhEY7t8vFxMEYH8AUj6VBXV"},
		{common.XRP, testECDSAPublicKey, "rwm9JugWgFHnKoUmVRNDjuUwBsb3w5v6XG"},
		{common.Solana, testEdDSAPublicKey, "9n22P31fnT9HscWos3jLEgvPG4HHwQehMJ8dhby18hcy"},
		{common.Sui, testEdDSAPublicKey, "0x2a5eb4cbdc14bfffb5cad5afe22a335e5860c20f2cf48be1d06062b53b27e2ce"},
		{common.Polkadot, testEdDSAPublicKey, "13wyTqpCftZqCj9uRHxpjYrMpJzotBsr1nXdNXVXRfj1s9Gs"},
		{common.Bittensor, testEdDSAPublicKey, "5F1gKWZ8p7JMmC9PTeupbQ2Cxh1ABtKhwHo9DEWAsahVgVnU"},
		{common.Cardano, testEdDSAPublicKey, "addr1v8r9wtl43a6e2hn89xsgmgv3ccjmtud9psf7mkn3gy9l7gc7svmds"},
		{common.Ton, testEdDSAPublicKey, "UQCffA0At2bHaJ9jbtjkfekp4gq3JxU411fRGeJe80nGm8rx"},
	}

	failed := 0
	for _, tc := range cases {
		addr, _, _, err := address.GetAddress(tc.rootKey, testHexChainCode, tc.chain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", tc.chain, err)
			failed++
			continue
		}
		if addr != tc.expected {
			fmt.Fprintf(os.Stderr, "FAIL %s: got %s, want %s\n", tc.chain, addr, tc.expected)
			failed++
			continue
		}
		fmt.Printf("OK   %s: %s\n", tc.chain, addr)
	}

	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d/%d tests failed\n", failed, len(cases))
		os.Exit(1)
	}
	fmt.Printf("\nAll %d address derivations passed\n", len(cases))
}
