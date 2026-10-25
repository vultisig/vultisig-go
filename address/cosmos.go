package address

import (
	"encoding/hex"
	"fmt"

	"github.com/vultisig/vultisig-go/encoding"
)

// GetBech32Address returns the bech32 address of the given hex public key
func GetBech32Address(hexPublicKey string, hrp string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("fail to decode hex public key,err: %w", err)
	}
	return encoding.Bech32EncodeBytes(hrp, hash160(pubKeyBytes))
}
