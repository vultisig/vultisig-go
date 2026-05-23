package address

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// GetSuiAddress generates a Sui address from a 32-byte Ed25519 public key.
//
// Sui addresses are blake2b-256(0x00 || pubkey) hex-encoded with `0x`
// prefix. The 32-byte length guard catches the bug shape where a
// 33-byte ECDSA pubkey was passed: pre-guard, the function happily
// blake2b'd the ECDSA bytes and produced an indistinguishable-looking
// 64-hex-char string that no real Sui account holds.
func GetSuiAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid public key: %w", err)
	}
	if len(pubKeyBytes) != 32 {
		return "", fmt.Errorf(
			"Sui requires a 32-byte Ed25519 public key, got %d bytes (passed a compressed ECDSA pubkey instead?)",
			len(pubKeyBytes),
		)
	}
	toHash := make([]byte, 0, len(pubKeyBytes)+1)
	toHash = append(toHash, 0x00)
	toHash = append(toHash, pubKeyBytes...)
	hashed := blake2b.Sum256(toHash)
	address := hex.EncodeToString(hashed[:])

	return "0x" + address, nil
}
