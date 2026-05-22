package address

import (
	"fmt"

	"github.com/vultisig/mobile-tss-lib/tss"

	"github.com/vultisig/vultisig-go/common"
)

// GetAddress returns the address, public key, isEdDSA, and error for the given public key and chain.
//
// `rootHexPublicKey` is interpreted PER CHAIN FAMILY:
//   - For ECDSA chains (Bitcoin, EVM, Cosmos-family, Tron, XRP, …) it MUST
//     be the 33-byte (66 hex chars) compressed secp256k1 root pubkey. The
//     function then BIP-32 derives along `chain.GetDerivePath()`.
//   - For EdDSA chains (Solana, Sui, Polkadot, Ton, Cardano, Bittensor) it
//     MUST be the 32-byte (64 hex chars) Ed25519 root pubkey. It is used
//     directly with NO derivation step (Vultisig's MPC stack treats the
//     EdDSA share's root key as the wallet key for these chains).
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
func GetAddress(rootHexPublicKey string, rootChainCode string, chain common.Chain) (address string, publicKey string, isEdDSA bool, err error) {
	if len(rootHexPublicKey) != 66 && len(rootHexPublicKey) != 64 {
		return "", "", false, fmt.Errorf("invalid public key: %s", rootHexPublicKey)
	}

	if !chain.IsEdDSA() {
		// ECDSA chains require the 33-byte (66 hex chars) compressed
		// secp256k1 root pubkey. A caller that passes a 32-byte EdDSA
		// pubkey here would silently re-derive nonsense via BIP-32.
		if len(rootHexPublicKey) != 66 {
			return "", "", false, fmt.Errorf(
				"ECDSA chain %q requires a 33-byte (66 hex chars) compressed secp256k1 root pubkey, got %d hex chars",
				chain, len(rootHexPublicKey),
			)
		}
		publicKey, err = tss.GetDerivedPubKey(rootHexPublicKey, rootChainCode, chain.GetDerivePath(), chain.IsEdDSA())
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
				chain, len(rootHexPublicKey),
			)
		}
		publicKey = rootHexPublicKey
	}

	switch chain {
	case common.Bitcoin:
		address, err = GetBitcoinAddress(publicKey)
		return address, publicKey, chain.IsEdDSA(), err
	case common.BitcoinCash:
		address, err = GetBitcoinCashAddress(publicKey)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Litecoin:
		address, err = GetLitecoinAddress(publicKey)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Dogecoin:
		address, err = GetDogecoinAddress(publicKey)
		return address, publicKey, chain.IsEdDSA(), err
	case common.GaiaChain:
		address, err = GetBech32Address(publicKey, `cosmos`)
		return address, publicKey, chain.IsEdDSA(), err
	case common.THORChain:
		address, err = GetBech32Address(publicKey, `thor`)
		return address, publicKey, chain.IsEdDSA(), err
	case common.MayaChain:
		address, err = GetBech32Address(publicKey, `maya`)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Kujira:
		address, err = GetBech32Address(publicKey, `kujira`)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Dydx:
		address, err = GetBech32Address(publicKey, `dydx`)
		return address, publicKey, chain.IsEdDSA(), err
	case common.TerraClassic, common.Terra:
		address, err = GetBech32Address(publicKey, `terra`)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Osmosis:
		address, err = GetBech32Address(publicKey, `osmo`)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Noble:
		address, err = GetBech32Address(publicKey, `noble`)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Akash:
		address, err = GetBech32Address(publicKey, `akash`)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Arbitrum, common.Base, common.BscChain, common.Ethereum, common.Polygon, common.Blast, common.Avalanche, common.Optimism, common.CronosChain, common.Zksync, common.Mantle, common.Hyperliquid, common.Sei:
		address, err = GetEVMAddress(publicKey)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Sui:
		address, err = GetSuiAddress(publicKey)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Solana:
		address, err = GetSolAddress(publicKey)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Zcash:
		address, err = GetZcashAddress(publicKey)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Dash:
		address, err = GetDashAddress(publicKey)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Tron:
		address, err = GetTronAddress(publicKey)
		return address, publicKey, chain.IsEdDSA(), err
	case common.XRP:
		address, err = GetXRPAddress(publicKey)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Polkadot:
		address, err = GetDotAddress(publicKey)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Bittensor:
		address, err = GetBittensorAddress(publicKey)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Cardano:
		address, err = GetCardanoAddress(publicKey)
		return address, publicKey, chain.IsEdDSA(), err
	case common.Ton:
		address, err = GetTonAddress(publicKey)
		return address, publicKey, chain.IsEdDSA(), err
	default:
		return "", "", false, fmt.Errorf("unsupported chain: %s", chain)
	}
}
