package address

import (
	"encoding/hex"
	"fmt"
)

func GetLitecoinAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}
	return p2wpkhAddress("ltc", pubKeyBytes)
}
