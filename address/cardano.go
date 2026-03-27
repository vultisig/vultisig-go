package address

import (
	"encoding/hex"
	"fmt"
)

func GetCardanoAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid EdDSA public key: %w", err)
	}
	if len(pubKeyBytes) != 32 {
		return "", fmt.Errorf("invalid public key length: expected 32 bytes, got %d", len(pubKeyBytes))
	}

	// Blake2b-224 hash of the spending key
	hasher := blake2bNew(28)
	hasher.Write(pubKeyBytes)
	keyHash := hasher.Sum(nil)

	// Prepend header byte 0x61 (enterprise address on mainnet)
	addressData := make([]byte, 29)
	addressData[0] = 0x61
	copy(addressData[1:], keyHash)

	return bech32ifyAddressBytes("addr", addressData)
}
