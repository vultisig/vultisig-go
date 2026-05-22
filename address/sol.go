package address

import (
	"encoding/hex"
	"fmt"

	"github.com/cosmos/btcutil/base58"
)

// GetSolAddress encodes a 32-byte Ed25519 pubkey as a Solana base58 address.
//
// The length guard catches the bug shape where a 33-byte compressed
// secp256k1 (ECDSA) pubkey was passed instead of the 32-byte Ed25519
// pubkey: pre-guard, the function happily base58-encoded the ECDSA
// bytes and produced a 44-char string that LOOKS like a Solana address
// but is actually the ECDSA pubkey. Solana RPC then rejected every
// lookup with `Invalid param: WrongSize`. Fail loud at this layer too —
// `GetAddress` already guards at the dispatch boundary, but this
// helper is callable directly and shouldn't silently misbehave.
func GetSolAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived EdDSA public key: %w", err)
	}
	if len(pubKeyBytes) != 32 {
		return "", fmt.Errorf(
			"Solana requires a 32-byte Ed25519 public key, got %d bytes (passed a compressed ECDSA pubkey instead?)",
			len(pubKeyBytes),
		)
	}
	return base58.Encode(pubKeyBytes), nil
}
