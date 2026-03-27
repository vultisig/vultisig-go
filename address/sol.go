package address

import (
	"encoding/hex"
	"fmt"
)

func GetSolAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived EdDSA public key: %w", err)
	}
	return base58Encode(pubKeyBytes), nil
}
