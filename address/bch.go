package address

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/vultisig/vultisig-go/encoding"
)

const bitcoinCashPrefix = "bitcoincash"

// GetBitcoinCashAddress returns the cashaddr P2PKH address without the
// "bitcoincash:" prefix.
func GetBitcoinCashAddress(hexPublicKey string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}
	addr, err := encoding.CashAddrEncode(bitcoinCashPrefix, encoding.CashAddrP2PKH, hash160(pubKeyBytes))
	if err != nil {
		return "", fmt.Errorf("fail to get public key hash: %w", err)
	}
	return strings.TrimPrefix(addr, bitcoinCashPrefix+":"), nil
}
