package address

import (
	"fmt"

	"github.com/vultisig/vultisig-go/common/chain"
)

// GetAddress returns the address, public key, isEdDSA, and error for the given public key and chain.
func GetAddress(rootHexPublicKey string, rootChainCode string, c chain.Chain) (address string, publicKey string, isEdDSA bool, err error) {
	if len(rootHexPublicKey) != 66 && len(rootHexPublicKey) != 64 {
		return "", "", false, fmt.Errorf("invalid public key: %s", rootHexPublicKey)
	}

	if !c.IsEdDSA() {
		publicKey, err = getDerivedPubKey(rootHexPublicKey, rootChainCode, c.GetDerivePath())
		if err != nil {
			return "", "", false, fmt.Errorf("failed to derive public key: %w", err)
		}
	} else {
		publicKey = rootHexPublicKey
	}

	switch c {
	case chain.Bitcoin:
		address, err = GetBitcoinAddress(publicKey)
		return address, publicKey, c.IsEdDSA(), err
	case chain.BitcoinCash:
		address, err = GetBitcoinCashAddress(publicKey)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Litecoin:
		address, err = GetLitecoinAddress(publicKey)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Dogecoin:
		address, err = GetDogecoinAddress(publicKey)
		return address, publicKey, c.IsEdDSA(), err
	case chain.GaiaChain:
		address, err = GetBech32Address(publicKey, `cosmos`)
		return address, publicKey, c.IsEdDSA(), err
	case chain.THORChain:
		address, err = GetBech32Address(publicKey, `thor`)
		return address, publicKey, c.IsEdDSA(), err
	case chain.MayaChain:
		address, err = GetBech32Address(publicKey, `maya`)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Kujira:
		address, err = GetBech32Address(publicKey, `kujira`)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Dydx:
		address, err = GetBech32Address(publicKey, `dydx`)
		return address, publicKey, c.IsEdDSA(), err
	case chain.TerraClassic, chain.Terra:
		address, err = GetBech32Address(publicKey, `terra`)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Osmosis:
		address, err = GetBech32Address(publicKey, `osmo`)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Noble:
		address, err = GetBech32Address(publicKey, `noble`)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Akash:
		address, err = GetBech32Address(publicKey, `akash`)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Arbitrum, chain.Base, chain.BscChain, chain.Ethereum, chain.Polygon, chain.Blast, chain.Avalanche, chain.Optimism, chain.CronosChain, chain.Zksync, chain.Mantle, chain.Hyperliquid, chain.Sei:
		address, err = GetEVMAddress(publicKey)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Sui:
		address, err = GetSuiAddress(publicKey)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Solana:
		address, err = GetSolAddress(publicKey)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Zcash:
		address, err = GetZcashAddress(publicKey)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Dash:
		address, err = GetDashAddress(publicKey)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Tron:
		address, err = GetTronAddress(publicKey)
		return address, publicKey, c.IsEdDSA(), err
	case chain.XRP:
		address, err = GetXRPAddress(publicKey)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Polkadot:
		address, err = GetDotAddress(publicKey)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Bittensor:
		address, err = GetBittensorAddress(publicKey)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Cardano:
		address, err = GetCardanoAddress(publicKey)
		return address, publicKey, c.IsEdDSA(), err
	case chain.Ton:
		address, err = GetTonAddress(publicKey)
		return address, publicKey, c.IsEdDSA(), err
	default:
		return "", "", false, fmt.Errorf("unsupported chain: %s", c)
	}
}
