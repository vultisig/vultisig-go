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
    "github.com/vultisig/vultisig-go/common"
)

addr, pubKey, isEdDSA, err := address.GetAddress(hexPublicKey, chainCode, common.Bitcoin)
```

Supported chains: Bitcoin, Bitcoin Cash, Litecoin, Dogecoin, Dash, Zcash, Ethereum (+ Arbitrum, Base, Optimism, Polygon, BSC, Avalanche, Blast, Cronos, zkSync, Mantle, Hyperliquid, Sei), Cosmos (+ THORChain, MayaChain, Kujira, Dydx, Terra, Osmosis, Noble, Akash), Solana, Sui, Polkadot, Bittensor, Cardano, TON, XRP, Tron.

### `common`

Chain definitions, vault encryption/decryption (AES-GCM), data compression (XZ), and shared utilities.

```go
import "github.com/vultisig/vultisig-go/common"

// Chain metadata
chain := common.Bitcoin
derivePath := chain.GetDerivePath()  // "m/84'/0'/0'/0/0"
isEdDSA := chain.IsEdDSA()           // false
evmID, _ := common.Ethereum.EvmID()  // 1

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
