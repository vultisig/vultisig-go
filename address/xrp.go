package address

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Base58 alphabet used by XRP
const xrpAlphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

// cosmos/btcutil/base58 alphabet
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func GetXRPAddress(hexPublicKey string) (string, error) {
	publicKey, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid hex public key: %v", err)
	}

	// Hash160 (SHA256 → RIPEMD160) then base58check with version 0x00
	h160 := hash160(publicKey)
	data := append([]byte{0}, h160...)
	base58Addr := base58CheckEncode(data)

	// Translate from standard base58 alphabet to XRP alphabet
	result := make([]byte, len(base58Addr))
	for i, b := range []byte(base58Addr) {
		index := strings.IndexByte(base58Alphabet, b)
		if index == -1 || index >= len(xrpAlphabet) {
			return "", fmt.Errorf("invalid base58 character: %s", string(b))
		}
		result[i] = xrpAlphabet[index]
	}
	return string(result), nil
}
