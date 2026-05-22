package address

import (
	"encoding/hex"
	"fmt"
)

// GetDotAddress SS58-encodes a 32-byte Ed25519 pubkey as a Polkadot
// mainnet address (network prefix 0). Length guard catches the
// ECDSA-pubkey-mistaken-for-EdDSA bug — see `GetSolAddress` for the
// full rationale.
func GetDotAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived EdDSA public key: %w", err)
	}
	if len(pubKeyBytes) != 32 {
		return "", fmt.Errorf(
			"Polkadot requires a 32-byte Ed25519 public key, got %d bytes (passed a compressed ECDSA pubkey instead?)",
			len(pubKeyBytes),
		)
	}
	return SS58Encode(pubKeyBytes, 0)
}
