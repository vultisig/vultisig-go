package address

import (
	"encoding/hex"
	"fmt"

	"github.com/vultisig/vultisig-go/encoding"
)

// Base58 alphabet used by XRP
const xrpAlphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

func GetXRPAddress(hexPublicKey string) (string, error) {
	publicKey, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid hex public key: %v", err)
	}
	// Account ID: version byte 0x00 + hash160, base58check in XRP's alphabet
	return encoding.Base58CheckEncodeAlphabet(append([]byte{0}, hash160(publicKey)...), xrpAlphabet), nil
}
