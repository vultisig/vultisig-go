package address

import (
	"encoding/hex"
	"fmt"
)

func GetBitcoinAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}
	return p2wpkhAddress("bc", pubKeyBytes)
}
