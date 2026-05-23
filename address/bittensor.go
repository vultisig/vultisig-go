package address

import (
	"encoding/hex"
	"fmt"
)

// GetBittensorAddress SS58-encodes a 32-byte Ed25519 pubkey as a
// Bittensor address (network prefix 42). Length guard catches the
// ECDSA-mistaken-for-EdDSA bug — see `GetSolAddress` for full rationale.
func GetBittensorAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived EdDSA public key: %w", err)
	}
	if len(pubKeyBytes) != 32 {
		return "", fmt.Errorf(
			"Bittensor requires a 32-byte Ed25519 public key, got %d bytes (passed a compressed ECDSA pubkey instead?)",
			len(pubKeyBytes),
		)
	}
	return SS58Encode(pubKeyBytes, 42)
}
