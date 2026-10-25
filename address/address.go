package address

import (
	"fmt"

	"github.com/vultisig/vultisig-go/common/chain"
)

// GetAddress returns the address, public key, isEdDSA, and error for the given public key and chain.
//
// `rootHexPublicKey` is interpreted PER CHAIN FAMILY:
//   - For ECDSA chains (Bitcoin, EVM, Cosmos-family, Tron, XRP, …) it MUST
//     be the 33-byte (66 hex chars) compressed secp256k1 root pubkey. The
//     function then BIP-32 derives along `c.GetDerivePath()`.
//   - For EdDSA chains (Solana, Sui, Polkadot, Ton, Cardano, Bittensor,
//     Near) it MUST be the 32-byte (64 hex chars) Ed25519 root pubkey. It
//     is used directly with NO derivation step (Vultisig's MPC stack
//     treats the EdDSA share's root key as the wallet key for these chains).
//   - For ML-DSA chains (QBTC) it MUST be the vault's 1312-byte ML-DSA-44
//     pubkey. It is used directly; `rootChainCode` is ignored.
//
// **Common bug shape** (caught 2026-05-22 in agent-backend's `addressbook`
// path): callers that only have the ECDSA pubkey on hand passed it for
// EdDSA chains too. The chain-specific helpers (`GetSolAddress`,
// `GetSuiAddress`, `GetDotAddress`, `GetBittensorAddress`) blindly
// base58/blake2b'd whatever bytes they got, silently producing addresses
// that decode to the ECDSA pubkey — confidently wrong, no error surfaced.
// The 33-vs-32 byte length guards below catch the misuse at the dispatch
// boundary so the failure is loud and actionable instead of garbage data
// in `user_addresses`.
func GetAddress(rootHexPublicKey string, rootChainCode string, c chain.Chain) (address string, publicKey string, isEdDSA bool, err error) {
	if c.IsMLDSA() {
		address, err = GetQBTCAddress(rootHexPublicKey)
		if err != nil {
			return "", "", false, err
		}
		return address, rootHexPublicKey, false, nil
	}

	if len(rootHexPublicKey) != 66 && len(rootHexPublicKey) != 64 {
		return "", "", false, fmt.Errorf("invalid public key: %s", rootHexPublicKey)
	}

	if !c.IsEdDSA() {
		// ECDSA chains require the 33-byte (66 hex chars) compressed
		// secp256k1 root pubkey. A caller that passes a 32-byte EdDSA
		// pubkey here would silently re-derive nonsense via BIP-32.
		if len(rootHexPublicKey) != 66 {
			return "", "", false, fmt.Errorf(
				"ECDSA chain %q requires a 33-byte (66 hex chars) compressed secp256k1 root pubkey, got %d hex chars",
				c, len(rootHexPublicKey),
			)
		}
		publicKey, err = getDerivedPubKey(rootHexPublicKey, rootChainCode, c.GetDerivePath())
		if err != nil {
			return "", "", false, fmt.Errorf("failed to derive public key: %w", err)
		}
	} else {
		// EdDSA chains require the 32-byte (64 hex chars) Ed25519 root
		// pubkey. A caller that passes the 33-byte ECDSA pubkey here is
		// the bug shape from agent-backend's pre-2026-05 addressbook
		// path — every Solana / Sui / Polkadot / Ton / Cardano /
		// Bittensor address it stored was the ECDSA pubkey
		// base58/blake2b'd. Fail loud rather than emit a confidently-
		// wrong address that decodes to a real-looking string but
		// belongs to no on-chain account.
		if len(rootHexPublicKey) != 64 {
			return "", "", false, fmt.Errorf(
				"EdDSA chain %q requires a 32-byte (64 hex chars) Ed25519 root pubkey, got %d hex chars (a compressed ECDSA pubkey was passed instead?)",
				c, len(rootHexPublicKey),
			)
		}
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
	case chain.Arbitrum, chain.Base, chain.BscChain, chain.Ethereum, chain.Polygon, chain.Blast, chain.Avalanche, chain.Optimism, chain.CronosChain, chain.Zksync, chain.Mantle, chain.Hyperliquid, chain.Sei, chain.Robinhood:
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
	case chain.Near:
		address, err = GetNearAddress(publicKey)
		return address, publicKey, c.IsEdDSA(), err
	default:
		return "", "", false, fmt.Errorf("unsupported chain: %s", c)
	}
}
