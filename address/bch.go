package address

import (
	"encoding/hex"
	"fmt"

	"github.com/vultisig/vultisig-go/encoding"
)

func GetBitcoinCashAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}
	pubKeyHash := hash160(pubKeyBytes)
	addr, err := encoding.CashAddrEncode("bitcoincash", 0x00, pubKeyHash)
	if err != nil {
		return "", err
	}
	// Strip "bitcoincash:" prefix to match EncodeAddress behavior.
	return addr[len("bitcoincash:"):], nil
}
