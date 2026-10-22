package address

import (
	"encoding/hex"
	"fmt"
)

// GetNearAddress returns the NEAR implicit account ID for a 32-byte
// Ed25519 public key: the lowercase hex encoding of the key itself.
//
// Like the other EdDSA helpers, it rejects a 33-byte compressed ECDSA
// pubkey rather than hex-encoding it into a 66-char string that is not
// a valid implicit account.
func GetNearAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid public key: %w", err)
	}
	if len(pubKeyBytes) != 32 {
		return "", fmt.Errorf(
			"NEAR requires a 32-byte Ed25519 public key, got %d bytes (passed a compressed ECDSA pubkey instead?)",
			len(pubKeyBytes),
		)
	}
	return hex.EncodeToString(pubKeyBytes), nil
}
