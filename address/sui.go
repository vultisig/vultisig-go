package address

import (
	"encoding/hex"
	"fmt"
)

// GetSuiAddress generates a Sui address from a hex-encoded public key
func GetSuiAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid public key: %w", err)
	}
	toHash := make([]byte, 0, len(pubKeyBytes)+1)
	toHash = append(toHash, 0x00)
	toHash = append(toHash, pubKeyBytes...)
	hashed := blake2bSum256(toHash)
	address := hex.EncodeToString(hashed[:])
	return "0x" + address, nil
}
