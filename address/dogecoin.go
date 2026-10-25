package address

import (
	"encoding/hex"
	"fmt"

	"github.com/vultisig/vultisig-go/encoding"
)

// DogecoinMainNetAddressPrefix is the version byte for Dogecoin P2PKH
// addresses (D...).
const DogecoinMainNetAddressPrefix = byte(0x1E)

func GetDogecoinAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}

	// Dogecoin uses P2PKH addresses (no native SegWit support)
	data := append([]byte{DogecoinMainNetAddressPrefix}, hash160(pubKeyBytes)...)
	return encoding.Base58CheckEncode(data), nil
}
