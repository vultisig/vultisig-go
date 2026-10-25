# vultisig-go

Shared Go packages for the [Vultisig](https://vultisig.com) ecosystem. Provides address derivation, chain metadata, vault encryption, and relay communication utilities.

## Installation

```bash
go get github.com/vultisig/vultisig-go
```

## Packages

### `address`

Derives addresses from ECDSA/EdDSA public keys for 30+ chains.

```go
import (
    "github.com/vultisig/vultisig-go/address"
    "github.com/vultisig/vultisig-go/common/chain"
)

addr, pubKey, isEdDSA, err := address.GetAddress(hexPublicKey, chainCode, chain.Bitcoin)
```

Supported chains: Bitcoin, Bitcoin Cash, Litecoin, Dogecoin, Dash, Zcash, Ethereum (+ Arbitrum, Base, Optimism, Polygon, BSC, Avalanche, Blast, Cronos, zkSync, Mantle, Hyperliquid, Sei, Robinhood), Cosmos (+ THORChain, MayaChain, Kujira, Dydx, Terra, Osmosis, Noble, Akash), Solana, Sui, Polkadot, Bittensor, Cardano, TON, NEAR, XRP, Tron, QBTC (from the vault's ML-DSA-44 key).

### `common/chain`

Chain definitions and per-chain metadata. Standard library only, so it is cheap to import.

```go
import "github.com/vultisig/vultisig-go/common/chain"

c := chain.Bitcoin
derivePath := c.GetDerivePath()     // "m/84'/0'/0'/0/0"
isEdDSA := c.IsEdDSA()              // false
evmID, _ := chain.Ethereum.EvmID()  // 1
```

### `common`

Vault encryption/decryption (AES-GCM), data compression (XZ), and shared utilities. `common.Chain` and the chain constants are aliases for `common/chain`, kept for compatibility.

```go
import "github.com/vultisig/vultisig-go/common"

// Vault encryption
encrypted, err := common.EncryptVault("password", vaultBytes)
decrypted, err := common.DecryptVault("password", encrypted)

// Decrypt from backup file
vault, err := common.DecryptVaultFromBackup("password", backupRaw)
```

### `relay`

Client for the Vultisig relay server, used for coordinating multi-party key generation and signing sessions.

```go
import "github.com/vultisig/vultisig-go/relay"

client := relay.NewRelayClient("https://relay.vultisig.com")
err := client.StartSession(sessionID, parties)
```

### `types`

Shared type definitions for vault creation, retrieval, and resharing requests/responses.

```go
import "github.com/vultisig/vultisig-go/types"

req := types.VaultCreateRequest{
    Name:             "my-vault",
    SessionID:        sessionID,
    HexEncryptionKey: hexKey,
    HexChainCode:     hexChainCode,
}
err := req.IsValid()
```

## License

See [LICENSE](LICENSE) for details.
