package common

import "github.com/vultisig/vultisig-go/common/chain"

// Chain is a type alias so existing code using common.Chain still works.
type Chain = chain.Chain

// Re-export all chain constants.
const (
	Undefined   = chain.Undefined
	THORChain   = chain.THORChain
	Solana      = chain.Solana
	Ethereum    = chain.Ethereum
	Avalanche   = chain.Avalanche
	BscChain    = chain.BscChain
	Bitcoin     = chain.Bitcoin
	BitcoinCash = chain.BitcoinCash
	Litecoin    = chain.Litecoin
	Dogecoin    = chain.Dogecoin
	GaiaChain   = chain.GaiaChain
	Kujira      = chain.Kujira
	Dash        = chain.Dash
	MayaChain   = chain.MayaChain
	Arbitrum    = chain.Arbitrum
	Base        = chain.Base
	Optimism    = chain.Optimism
	Polygon     = chain.Polygon
	Blast       = chain.Blast
	CronosChain = chain.CronosChain
	Sui         = chain.Sui
	Polkadot    = chain.Polkadot
	Zksync      = chain.Zksync
	Dydx        = chain.Dydx
	Ton         = chain.Ton
	Terra       = chain.Terra
	TerraClassic = chain.TerraClassic
	XRP         = chain.XRP
	Osmosis     = chain.Osmosis
	Noble       = chain.Noble
	Tron        = chain.Tron
	Mantle      = chain.Mantle
	Zcash       = chain.Zcash
	Bittensor   = chain.Bittensor
	Cardano     = chain.Cardano
	Akash       = chain.Akash
	Hyperliquid = chain.Hyperliquid
	Sei         = chain.Sei
)

// Re-export FromString.
var FromString = chain.FromString
