package address

import (
	"encoding/hex"
	"fmt"
)

// MLDSA44PublicKeySize is the byte length of an ML-DSA-44 public key.
const MLDSA44PublicKeySize = 1312

// GetQBTCAddress returns the QBTC address for an ML-DSA-44 public key:
// Bech32("qbtc", RIPEMD160(SHA256(pubkey))), the Cosmos SDK scheme
// applied to the vault's post-quantum key.
func GetQBTCAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid public key: %w", err)
	}
	if len(pubKeyBytes) != MLDSA44PublicKeySize {
		return "", fmt.Errorf(
			"QBTC requires a %d-byte ML-DSA-44 public key, got %d bytes",
			MLDSA44PublicKeySize, len(pubKeyBytes),
		)
	}
	return GetBech32Address(hexPublicKey, `qbtc`)
}
