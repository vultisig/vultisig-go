package address

import (
	"encoding/hex"
	"fmt"
)

func GetDogecoinAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}

	// Dogecoin uses P2PKH addresses with version byte 0x1E (starts with D)
	pubKeyHash := hash160(pubKeyBytes)
	data := append([]byte{0x1E}, pubKeyHash...)
	return base58CheckEncode(data), nil
}
