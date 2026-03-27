package address

import (
	"encoding/hex"
	"fmt"
)

// GetBech32Address returns the bech32 address of the given hex public key
func GetBech32Address(hexPublicKey string, hrp string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("fail to decode hex public key,err: %w", err)
	}
	pubKeyHash := hash160(pubKeyBytes)
	return bech32ifyAddressBytes(hrp, pubKeyHash)
}
