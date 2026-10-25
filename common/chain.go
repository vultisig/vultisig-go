package common

import "github.com/vultisig/vultisig-go/common/chain"

// Chain is an alias for chain.Chain, kept so existing common.Chain users
// keep compiling. New code that only needs chain metadata should import
// common/chain directly to avoid this package's dependencies.
type Chain = chain.Chain

const (
	Undefined    = chain.Undefined
	THORChain    = chain.THORChain
	Solana       = chain.Solana
	Ethereum     = chain.Ethereum
	Avalanche    = chain.Avalanche
	BscChain     = chain.BscChain
	Bitcoin      = chain.Bitcoin
	BitcoinCash  = chain.BitcoinCash
	Litecoin     = chain.Litecoin
	Dogecoin     = chain.Dogecoin
	GaiaChain    = chain.GaiaChain
	Kujira       = chain.Kujira
	Dash         = chain.Dash
	MayaChain    = chain.MayaChain
	Arbitrum     = chain.Arbitrum
	Base         = chain.Base
	Optimism     = chain.Optimism
	Polygon      = chain.Polygon
	Blast        = chain.Blast
	CronosChain  = chain.CronosChain
	Sui          = chain.Sui
	Polkadot     = chain.Polkadot
	Zksync       = chain.Zksync
	Dydx         = chain.Dydx
	Ton          = chain.Ton
	Terra        = chain.Terra
	TerraClassic = chain.TerraClassic
	XRP          = chain.XRP
	Osmosis      = chain.Osmosis
	Noble        = chain.Noble
	Tron         = chain.Tron
	Mantle       = chain.Mantle
	Zcash        = chain.Zcash
	Bittensor    = chain.Bittensor
	Cardano      = chain.Cardano
	Akash        = chain.Akash
	Hyperliquid  = chain.Hyperliquid
	Sei          = chain.Sei
	Robinhood    = chain.Robinhood
	Near         = chain.Near
	QBTC         = chain.QBTC
)

// FromString is an alias for chain.FromString.
var FromString = chain.FromString
