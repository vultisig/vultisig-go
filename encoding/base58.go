package encoding

import (
	"crypto/sha256"
	"math/big"
)

// Standard Bitcoin/general-purpose Base58 alphabet.
const Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Base58Encode encodes data using the standard Bitcoin Base58 alphabet.
// No checksum is appended.
func Base58Encode(data []byte) string {
	return Base58EncodeAlphabet(data, Base58Alphabet)
}

// Base58EncodeAlphabet encodes data using a custom 58-character alphabet.
func Base58EncodeAlphabet(data []byte, alphabet string) string {
	// Count leading zero bytes — each becomes a leading '1' (first char of alphabet).
	var zeros int
	for _, b := range data {
		if b != 0 {
			break
		}
		zeros++
	}

	num := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	mod := new(big.Int)

	var result []byte
	for num.Sign() > 0 {
		num.DivMod(num, base, mod)
		result = append([]byte{alphabet[mod.Int64()]}, result...)
	}
	for i := 0; i < zeros; i++ {
		result = append([]byte{alphabet[0]}, result...)
	}
	return string(result)
}

// Base58CheckEncode appends a 4-byte double-SHA256 checksum and Base58-encodes
// using the standard alphabet. Used by Bitcoin P2PKH/P2SH, Zcash, Dash, Dogecoin, etc.
func Base58CheckEncode(data []byte) string {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	payload := append(data, second[:4]...)
	return Base58Encode(payload)
}
